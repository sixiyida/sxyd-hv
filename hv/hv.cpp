#include "hv.h"
#include "vcpu.h"
#include "mm.h"
#include "arch.h"
#include "shared-queue.h"

namespace hv {

hypervisor ghv;

extern "C" {

// function prototype doesn't really matter
// since we never call these functions anyways
NTKERNELAPI void PsGetCurrentThreadProcess();
NTKERNELAPI void PsGetProcessImageFileName();

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
  // TODO: maybe dont hardcode this...
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

  ghv.pool_tag = generate_pool_tag();

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
      // TODO: handle this bruh -_-
      KeRevertToUserAffinityThreadEx(orig_affinity);
      return false;
    }

    KeRevertToUserAffinityThreadEx(orig_affinity);
  }

  return true;
}

// devirtualize the current system
void stop() {
  // we need to be running at an IRQL below DISPATCH_LEVEL so
  // that KeSetSystemAffinityThreadEx takes effect immediately
  NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

  if (!ghv.vcpus || ghv.vcpu_count == 0)
    return;

  // reset per-vcpu notification flags
  for (unsigned long i = 0; i < ghv.vcpu_count; ++i)
    ghv.vcpus[i].stop_notified = false;

  InterlockedExchange(const_cast<LONG*>(&ghv.stopped_cpu_count), 0);
  InterlockedExchange(const_cast<LONG*>(&ghv.stop_requested), 1);

  // wait for all vcpus to exit VMX (triggered on next VM-exit)
  LARGE_INTEGER interval;
  interval.QuadPart = -10 * 1000 * 10; // 10ms

  uint32_t spins = 0;
  while (static_cast<unsigned long>(ghv.stopped_cpu_count) < ghv.vcpu_count && spins++ < 1000) {
    KeDelayExecutionThread(KernelMode, FALSE, &interval);
  }

  if (static_cast<unsigned long>(ghv.stopped_cpu_count) < ghv.vcpu_count) {
    DbgPrint("[hv] stop(): timeout waiting for vcpus to devirtualize (%ld/%lu).\n",
      ghv.stopped_cpu_count, ghv.vcpu_count);
  }

  // 清空共享队列注册，避免残留 CR3/地址在停止后被误用
  clear_all_shared_queues();

  if (ghv.vcpus) {
    auto const tag = ghv.pool_tag ? ghv.pool_tag : static_cast<uint32_t>('enoN');
    ExFreePoolWithTag(ghv.vcpus, tag);
    ghv.vcpus = nullptr;
    ghv.vcpu_count = 0;
  }

  InterlockedExchange(const_cast<LONG*>(&ghv.stop_requested), 0);
}

} // namespace hv

