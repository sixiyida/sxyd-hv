#include "hv.h"
#include "shared-queue.h"

#include <ntddk.h>
#include <ia32.hpp>

void driver_unload(PDRIVER_OBJECT) {
  // 先停止虚拟化（避免 stop 过程中回调带来额外并发），再注销回调
  hv::stop();

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

  return STATUS_SUCCESS;
}

