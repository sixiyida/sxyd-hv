#include "hv.h"
#include "vcpu.h"
#include "mm.h"
#include "arch.h"
#include "shared-queue.h"
#include <ntimage.h>
#include <intrin.h>

namespace hv {
// EPT self-hide is experimental and can destabilize startup/unload on new kernels.
// Default: disabled.
#ifndef HV_ENABLE_EPT_SELF_HIDE
#define HV_ENABLE_EPT_SELF_HIDE 1
#endif

// EPT hide for shared-queue is also experimental:
// it remaps user pages to a dummy page in EPT when the owning CR3 is not running.
// Default: disabled.
#ifndef HV_ENABLE_EPT_SHARED_QUEUE_HIDE
#define HV_ENABLE_EPT_SHARED_QUEUE_HIDE 1
#endif
// Force a VM-exit on each logical processor by executing CPUID.
// This is used to make hv::stop() deterministic even when VM-exits are rare.
static ULONG_PTR ipi_kick_vmexit(ULONG_PTR /*ctx*/) {
  int info[4] = {};
  __cpuid(info, 0);
  return 0;
}

hypervisor ghv;

// incremented from vm-exit.asm (lock inc) after VMXOFF executes on a VCPU.
extern "C" volatile LONG g_hv_vmxoff_cpu_count = 0;

extern "C" {

// Only used for signature/byte-pattern scanning (we take the address; we don't call them).
NTKERNELAPI void PsGetCurrentThreadProcess();
NTKERNELAPI void PsGetProcessImageFileName();
extern "C" IMAGE_DOS_HEADER __ImageBase;
extern "C" PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID BaseAddress);

}

// generate a per-load pool tag to avoid static signatures
static uint32_t generate_pool_tag() {
  auto const counter = KeQueryPerformanceCounter(nullptr);
  uint32_t seed = static_cast<uint32_t>(counter.LowPart ^ counter.HighPart ^
    reinterpret_cast<uintptr_t>(&ghv));

  // simple LCG to avoid relying on RtlRandomEx declaration visibility
  seed = seed ? seed : 0x13579BDFu;
  seed = seed * 1664525u + 1013904223u;

  auto tag = seed;

  if (tag == 0)
    tag = 'enoN'; // fall back to a common kernel tag shape

  return tag;
}

// dynamically find the offsets for various kernel structures
static bool find_offsets() {
  // TODO: derive these offsets per build (PDB/symbols or more robust pattern scanning).
  ghv.kprocess_directory_table_base_offset = 0x28;
  ghv.kpcr_pcrb_offset                     = 0x180;
  ghv.kprcb_current_thread_offset          = 0x8;
  ghv.kapc_state_process_offset            = 0x20;

  ghv.system_eprocess = reinterpret_cast<uint8_t*>(PsInitialSystemProcess);

  DbgPrint("[hv] System EPROCESS = 0x%zX.\n",
    reinterpret_cast<size_t>(ghv.system_eprocess));

  auto const ps_get_process_id = reinterpret_cast<uint8_t*>(PsGetProcessId);

  // mov rax, [rcx + OFFSET]
  // retn
  if (ps_get_process_id[0] != 0x48 ||
      ps_get_process_id[1] != 0x8B ||
      ps_get_process_id[2] != 0x81 ||
      ps_get_process_id[7] != 0xC3) {
    DbgPrint("[hv] Failed to get EPROCESS::UniqueProcessId offset.\n");
    return false;
  }

  ghv.eprocess_unique_process_id_offset =
    *reinterpret_cast<uint32_t*>(ps_get_process_id + 3);

  DbgPrint("[hv] EPROCESS::UniqueProcessId offset = 0x%zX.\n",
    ghv.eprocess_unique_process_id_offset);

  auto const ps_get_process_image_file_name = reinterpret_cast<uint8_t*>(PsGetProcessImageFileName);

  // lea rax, [rcx + OFFSET]
  // retn
  if (ps_get_process_image_file_name[0] != 0x48 ||
      ps_get_process_image_file_name[1] != 0x8D ||
      ps_get_process_image_file_name[2] != 0x81 ||
      ps_get_process_image_file_name[7] != 0xC3) {
    DbgPrint("[hv] Failed to get EPROCESS::ImageFileName offset.\n");
    return false;
  }

  ghv.eprocess_image_file_name =
    *reinterpret_cast<uint32_t*>(ps_get_process_image_file_name + 3);

  DbgPrint("[hv] EPROCESS::ImageFileName offset = 0x%zX.\n",
    ghv.eprocess_image_file_name);

  auto const ps_get_current_thread_process =
    reinterpret_cast<uint8_t*>(PsGetCurrentThreadProcess);

  // mov rax, gs:188h
  // mov rax, [rax + OFFSET]
  // retn
  if (ps_get_current_thread_process[0]  != 0x65 ||
      ps_get_current_thread_process[1]  != 0x48 ||
      ps_get_current_thread_process[2]  != 0x8B ||
      ps_get_current_thread_process[3]  != 0x04 ||
      ps_get_current_thread_process[4]  != 0x25 ||
      ps_get_current_thread_process[9]  != 0x48 ||
      ps_get_current_thread_process[10] != 0x8B ||
      ps_get_current_thread_process[11] != 0x80) {
    DbgPrint("[hv] Failed to get KAPC_STATE::Process offset.\n");
    return false;
  }

  ghv.kapc_state_process_offset =
    *reinterpret_cast<uint32_t*>(ps_get_current_thread_process + 12);

  // store the System cr3 value (found in the System EPROCESS structure)
  ghv.system_cr3 = *reinterpret_cast<cr3*>(ghv.system_eprocess +
    ghv.kprocess_directory_table_base_offset);

  DbgPrint("[hv] System CR3 = 0x%zX.\n", ghv.system_cr3.flags);

  return true;
}

// allocate the hypervisor and vcpus
static bool create() {
  memset(&ghv, 0, sizeof(ghv));

  logger_init();

  // record hv image layout for EPT self-hiding
  {
    auto nt = RtlImageNtHeader(&__ImageBase);
    ghv.hv_image_base = &__ImageBase;
    ghv.hv_image_size = nt ? nt->OptionalHeader.SizeOfImage : 0;
  }

  ghv.pool_tag = generate_pool_tag();

  // precompute hv image PFNs before entering VMX operation (more stable than doing it in root-mode)
  // Only needed for EPT self-hide.
  ghv.hv_image_pfns = nullptr;
  ghv.hv_image_pfn_count = 0;
#if HV_ENABLE_EPT_SELF_HIDE
  if (ghv.hv_image_base && ghv.hv_image_size) {
    size_t const capped_size = (ghv.hv_image_size > 0x2000000ull) ? 0x2000000ull : ghv.hv_image_size;
    auto const start = reinterpret_cast<uintptr_t>(ghv.hv_image_base) & ~static_cast<uintptr_t>(0xFFF);
    auto const end = (reinterpret_cast<uintptr_t>(ghv.hv_image_base) + capped_size + 0xFFF) & ~static_cast<uintptr_t>(0xFFF);
    uint32_t const total_pages = static_cast<uint32_t>((end - start) >> 12);

    if (total_pages > 0 && total_pages < 4096) {
      auto* const pfns = static_cast<uint64_t*>(ExAllocatePoolWithTag(
        NonPagedPoolNx, total_pages * sizeof(uint64_t), ghv.pool_tag));
      if (pfns) {
        uint32_t count = 0;
        for (uintptr_t va = start; va < end; va += 0x1000) {
          auto const vptr = reinterpret_cast<void*>(va);
          __try {
            if (!MmIsAddressValid(vptr))
              continue;
            auto const phys = MmGetPhysicalAddress(vptr).QuadPart;
            if (!phys)
              continue;
            pfns[count++] = phys >> 12;
          } __except (1) {
            // skip faults while walking image pages
          }
        }

        ghv.hv_image_pfns = pfns;
        ghv.hv_image_pfn_count = count;
      }
    }
  }
#endif

  ghv.vcpu_count = KeQueryActiveProcessorCount(nullptr);

  // size of the vcpu array
  auto const arr_size = sizeof(vcpu) * ghv.vcpu_count;

  // allocate an array of vcpus
  ghv.vcpus = static_cast<vcpu*>(ExAllocatePoolWithTag(
    NonPagedPoolNx, arr_size, ghv.pool_tag));

  if (!ghv.vcpus) {
    DbgPrint("[hv] Failed to allocate VCPUs.\n");
    return false;
  }

  // zero-initialize the vcpu array
  memset(ghv.vcpus, 0, arr_size);

  DbgPrint("[hv] Allocated %u VCPUs (0x%zX bytes).\n", ghv.vcpu_count, arr_size);

  if (!find_offsets()) {
    DbgPrint("[hv] Failed to find offsets.\n");
    return false;
  }

  prepare_host_page_tables();

  DbgPrint("[hv] Mapped all of physical memory to address 0x%zX.\n",
    reinterpret_cast<uint64_t>(host_physical_memory_base));

  return true;
}

// virtualize the current system
bool start() {
  if (!create())
    return false;

  // we need to be running at an IRQL below DISPATCH_LEVEL so
  // that KeSetSystemAffinityThreadEx takes effect immediately
  NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

  // virtualize every cpu
  for (unsigned long i = 0; i < ghv.vcpu_count; ++i) {
    // restrict execution to the specified cpu
    auto const orig_affinity = KeSetSystemAffinityThreadEx(1ull << i);

    if (!virtualize_cpu(&ghv.vcpus[i])) {
      // TODO: unwind already-virtualized CPUs and free allocations before returning failure.
      KeRevertToUserAffinityThreadEx(orig_affinity);
      return false;
    }

    KeRevertToUserAffinityThreadEx(orig_affinity);
  }

  // Enable EPT self-hide AFTER startup so the guest can finish executing hv.sys code paths.
#if HV_ENABLE_EPT_SELF_HIDE
  InterlockedExchange(const_cast<LONG*>(&ghv.hide_pending), 1);
  DbgPrint("[hv] EPT self-hide pending (will apply on first VM-exit per VCPU).\n");
#else
  InterlockedExchange(const_cast<LONG*>(&ghv.hide_pending), 0);
#endif

  // Enable/disable shared-queue EPT hide (best-effort).
#if HV_ENABLE_EPT_SHARED_QUEUE_HIDE
  InterlockedExchange(const_cast<LONG*>(&ghv.sq_hide_enabled), 1);
  DbgPrint("[hv] EPT shared-queue hide enabled.\n");
#else
  InterlockedExchange(const_cast<LONG*>(&ghv.sq_hide_enabled), 0);
#endif

  return true;
}

// devirtualize the current system
void stop() {
  // we need to be running at an IRQL below DISPATCH_LEVEL so
  // that KeSetSystemAffinityThreadEx takes effect immediately
  NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

  if (!ghv.vcpus || ghv.vcpu_count == 0)
    return;

  // Prevent any further (re)hiding while we are stopping/unloading.
  InterlockedExchange(const_cast<LONG*>(&ghv.hide_pending), 0);

  // If VMX is already off on all CPUs (e.g. user-mode devirtualized each core via hypercall),
  // just do best-effort cleanup without trying to trigger new VM-exits.
  if (ghv.vcpus && ghv.vcpu_count &&
      static_cast<unsigned long>(g_hv_vmxoff_cpu_count) >= ghv.vcpu_count) {
    clear_all_shared_queues();

    if (ghv.hv_image_pfns) {
      auto const tag = ghv.pool_tag ? ghv.pool_tag : static_cast<uint32_t>('enoN');
      ExFreePoolWithTag(ghv.hv_image_pfns, tag);
      ghv.hv_image_pfns = nullptr;
      ghv.hv_image_pfn_count = 0;
    }

    auto const tag = ghv.pool_tag ? ghv.pool_tag : static_cast<uint32_t>('enoN');
    ExFreePoolWithTag(ghv.vcpus, tag);
    ghv.vcpus = nullptr;
    ghv.vcpu_count = 0;

    InterlockedExchange(const_cast<LONG*>(&ghv.stop_requested), 0);
    InterlockedExchange(const_cast<LONG*>(&ghv.hide_pending), 0);
    InterlockedExchange(const_cast<LONG*>(&g_hv_vmxoff_cpu_count), 0);
    return;
  }

  // reset per-vcpu notification flags
  for (unsigned long i = 0; i < ghv.vcpu_count; ++i) {
    ghv.vcpus[i].stop_notified = false;
  }

  InterlockedExchange(const_cast<LONG*>(&ghv.stopped_cpu_count), 0);
  InterlockedExchange(const_cast<LONG*>(&g_hv_vmxoff_cpu_count), 0);
  InterlockedExchange(const_cast<LONG*>(&ghv.stop_requested), 1);

  // IMPORTANT (EPT self-hide):
  // If hv.sys pages are hidden in the guest, using KeIpiGenericCall with a hv.sys function pointer
  // is unsafe because the guest would execute hidden hv.sys code. In self-hide mode, rely on
  // VMX preemption timer / normal VM-exits to observe stop_requested instead of IPI-calling hv.sys.
#if !HV_ENABLE_EPT_SELF_HIDE
  // Kick every CPU to ensure we get a VM-exit promptly and observe stop_requested.
  // Without this, stop can hang indefinitely if the guest isn't executing exit-causing instructions.
  KeIpiGenericCall(ipi_kick_vmexit, 0);
#endif

  // wait for all vcpus to execute VMXOFF (triggered on next VM-exit)
  LARGE_INTEGER interval;
  interval.QuadPart = -10 * 1000 * 10; // 10ms

  uint32_t spins = 0;
  while (static_cast<unsigned long>(g_hv_vmxoff_cpu_count) < ghv.vcpu_count && spins++ < 3000) {
    KeDelayExecutionThread(KernelMode, FALSE, &interval);
  }

  if (static_cast<unsigned long>(g_hv_vmxoff_cpu_count) < ghv.vcpu_count) {
    DbgPrint("[hv] stop(): timeout waiting for vcpus to VMXOFF (%ld/%lu, stopSeen=%ld).\n",
      g_hv_vmxoff_cpu_count, ghv.vcpu_count, ghv.stopped_cpu_count);
  }

  // 清空共享队列注册，避免残留 CR3/地址在停止后被误用
  clear_all_shared_queues();

  // If not all CPUs executed VMXOFF, do NOT free memory.
  // Freeing the VCPU array early can corrupt kernel memory and crash in IopUnloadDriver.
  if (static_cast<unsigned long>(g_hv_vmxoff_cpu_count) < ghv.vcpu_count)
    return;

  if (ghv.hv_image_pfns) {
    auto const tag = ghv.pool_tag ? ghv.pool_tag : static_cast<uint32_t>('enoN');
    ExFreePoolWithTag(ghv.hv_image_pfns, tag);
    ghv.hv_image_pfns = nullptr;
    ghv.hv_image_pfn_count = 0;
  }

  if (ghv.vcpus) {
    auto const tag = ghv.pool_tag ? ghv.pool_tag : static_cast<uint32_t>('enoN');
    ExFreePoolWithTag(ghv.vcpus, tag);
    ghv.vcpus = nullptr;
    ghv.vcpu_count = 0;
  }

  InterlockedExchange(const_cast<LONG*>(&ghv.stop_requested), 0);
}

void request_global_devirtualize() {
  // Best-effort: if we're not initialized, nothing to do.
  if (!ghv.vcpus || ghv.vcpu_count == 0)
    return;

  // Prevent any further (re)hiding while we are stopping/unloading.
  InterlockedExchange(const_cast<LONG*>(&ghv.hide_pending), 0);

  // Request devirtualization.
  InterlockedExchange(const_cast<LONG*>(&ghv.stop_requested), 1);

  // See comment in stop(): in EPT self-hide mode we must not IPI-call hv.sys code from the guest.
#if !HV_ENABLE_EPT_SELF_HIDE
  KeIpiGenericCall(ipi_kick_vmexit, 0);
#endif
}

} // namespace hv

