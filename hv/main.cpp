#include "hv.h"
#include "shared-queue.h"

#include <ntddk.h>
#include <ia32.hpp>

namespace {

// 进程退出回调：用进程的 DirectoryTableBase（CR3）去失效共享队列，
// 防止 um 退出/释放内存后 CR3 或物理页复用导致 HV 继续写“旧队列”从而破坏内核结构。
EXTERN_C void process_notify_ex(
  PEPROCESS Process,
  HANDLE /*ProcessId*/,
  PPS_CREATE_NOTIFY_INFO CreateInfo) {
  // CreateInfo != nullptr 表示创建；nullptr 表示退出
  if (CreateInfo)
    return;

  // 未启动/已停止则无需处理
  if (!hv::ghv.vcpus || hv::ghv.kprocess_directory_table_base_offset == 0)
    return;

  __try {
    auto const base = reinterpret_cast<uint8_t*>(Process);
    auto const dirbase = *reinterpret_cast<uint64_t const*>(
      base + hv::ghv.kprocess_directory_table_base_offset);
    ::cr3 proc_cr3;
    proc_cr3.flags = dirbase;
    hv::invalidate_shared_queue(proc_cr3);
  }
  __except (1) {
    // 避免回调引发 bugcheck
  }
}

} // namespace

// simple hypercall wrappers
static uint64_t ping() {
  hv::hypercall_input input;
  input.code = hv::hypercall_ping;
  input.key  = hv::hypercall_key;
  return hv::vmx_vmcall(input);
}

void driver_unload(PDRIVER_OBJECT) {
  // 先停止虚拟化（避免 stop 过程中回调带来额外并发），再注销回调
  hv::stop();

  (void)PsSetCreateProcessNotifyRoutineEx(process_notify_ex, TRUE);

  DbgPrint("[hv] Devirtualized the system.\n");
  DbgPrint("[hv] Driver unloaded.\n");
}

NTSTATUS driver_entry(PDRIVER_OBJECT const driver, PUNICODE_STRING) {
  DbgPrint("[hv] Driver loaded.\n");

  if (driver)
    driver->DriverUnload = driver_unload;

  if (!hv::start()) {
    DbgPrint("[hv] Failed to virtualize system.\n");
    return STATUS_HV_OPERATION_FAILED;
  }

  // 注册进程退出回调（仅用于清理 shared-queue 生命周期）
  auto const st = PsSetCreateProcessNotifyRoutineEx(process_notify_ex, FALSE);
  if (!NT_SUCCESS(st)) {
    DbgPrint("[hv] Failed to register process notify callback: 0x%08X.\n", st);
  }

  if (ping() == hv::hypervisor_signature)
    DbgPrint("[client] Hypervisor signature matches.\n");
  else
    DbgPrint("[client] Failed to ping hypervisor!\n");

  return STATUS_SUCCESS;
}

