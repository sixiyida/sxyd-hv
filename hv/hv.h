#pragma once

#include "page-tables.h"
#include "hypercalls.h"
#include "logger.h"
#include "vmx.h"

#include <ntddk.h>

namespace hv {

// signature that is returned by the ping hypercall
inline constexpr uint64_t hypervisor_signature = 'fr0g';

struct hypervisor {
  // host page tables that are shared between vcpus
  host_page_tables host_page_tables;

  // logger that can be used in root-mode
  logger logger;

  // dynamically allocated array of vcpus
  unsigned long vcpu_count;
  struct vcpu* vcpus;
  uint32_t pool_tag;

  // hv image info (for EPT self-hiding)
  void*  hv_image_base;
  size_t hv_image_size;
  uint64_t* hv_image_pfns;
  uint32_t  hv_image_pfn_count;

  // stop/devirtualization coordination (no VMCALL path)
  volatile LONG stop_requested;
  volatile LONG stopped_cpu_count;

  // EPT self-hide: enable after startup completes (applied lazily per-vcpu on first VM-exit)
  volatile LONG hide_pending;

  // EPT hide for shared-queue pages (best-effort; see shared-queue.cpp).
  // When enabled, shared-queue pages are unmapped (remapped to dummy_page) in EPT for
  // guest contexts that do not own the queue (based on CR3), and temporarily restored
  // for the owner on VM-exit boundaries (e.g. MOV CR3 / CPUID handshake).
  volatile LONG sq_hide_enabled;

  // pointer to the System process
  uint8_t* system_eprocess;

  // kernel CR3 value of the System process
  cr3 system_cr3;

  // windows specific offsets D:
  uint64_t kprocess_directory_table_base_offset;
  uint64_t eprocess_unique_process_id_offset;
  uint64_t eprocess_image_file_name;
  uint64_t kpcr_pcrb_offset;
  uint64_t kprcb_current_thread_offset;
  uint64_t kthread_apc_state_offset;
  uint64_t kapc_state_process_offset;
};

// global instance of the hypervisor
extern hypervisor ghv;

// virtualize the current system
bool start();

// devirtualize the current system
void stop();

// Request global devirtualization from root-mode (e.g. via shared queue command).
// This only sets the stop request and kicks all CPUs to get a VM-exit promptly.
void request_global_devirtualize();

} // namespace hv

