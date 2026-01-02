#pragma once

#include <cstdint>
#include <Windows.h>

namespace hv {

// key used for executing hypercalls
inline constexpr uint64_t hypercall_key = 69420;

// signature that is returned by the ping hypercall
inline constexpr uint64_t hypervisor_signature = 'fr0g';

struct logger_msg {
  static constexpr uint32_t max_msg_length = 128;

  // ID of the current message
  uint64_t id;

  // timestamp counter of the current message
  uint64_t tsc;

  // process ID of the VCPU that sent the message
  uint32_t aux;

  // null-terminated ascii string
  char data[max_msg_length];
};

// hypercall indices
enum hypercall_code : uint64_t {
  hypercall_ping = 0,
  hypercall_test,
  hypercall_unload,
  hypercall_read_phys_mem,
  hypercall_write_phys_mem,
  hypercall_read_virt_mem,
  hypercall_write_virt_mem,
  hypercall_query_process_cr3,
  hypercall_install_ept_hook,
  hypercall_remove_ept_hook,
  hypercall_flush_logs,
  hypercall_get_physical_address,
  hypercall_hide_physical_page,
  hypercall_unhide_physical_page,
  hypercall_get_hv_base,
  hypercall_install_mmr,
  hypercall_remove_mmr,
  hypercall_remove_all_mmrs
};

// CPUID 握手叶子（共享队列注册）
inline constexpr uint32_t shared_queue_cpuid_leaf               = 0x80000000;
inline constexpr uint32_t shared_queue_magic0                  = 0x9D2F4B1Au; // RCX
inline constexpr uint32_t shared_queue_magic1                  = 0xC3E15A7Bu; // RSI
inline constexpr uint32_t shared_queue_cpuid_subleaf_handshake = 0;

// 队列命令与状态（需与内核侧保持一致）
enum class shared_queue_cmd : uint32_t {
  nop = 0,
  read_phys,
  write_phys,
  read_virt,
  write_virt,
  // debug: query EPT mapping for a guest VA (returns PFNs)
  query_ept_map,
  // request global devirtualization (used when VMCALL/hypercalls are disabled)
  devirt_all,
  // fetch recent TSC diagnostic snapshots into a user-provided buffer
  tsc_diag_dump,
  // dump aggregated VM-exit/MSR statistics (best-effort)
  exit_stats_dump,
};

enum class shared_queue_entry_status : uint32_t {
  pending           = 0,
  done              = 1,
  err_unimplemented = 0x80000001,
  err_translate     = 0x80000002,
};

struct shared_queue_header {
  uint32_t head;
  uint32_t tail;
  uint32_t reserved0;
  uint32_t reserved1;
};

struct alignas(64) shared_queue_entry {
  uint32_t cmd;         // shared_queue_cmd
  uint32_t status;      // shared_queue_entry_status
  uint64_t cr3;         // 目标 CR3（可选）
  uint64_t gva;         // 虚拟地址
  uint64_t gpa;         // 物理地址（可选）
  uint32_t size;        // 操作尺寸
  uint32_t flags;       // 扩展标志
  uint64_t aux;         // 额外参数/返回值
  uint64_t reserved;    // 保留
};
static_assert(sizeof(shared_queue_entry) == 64, "shared_queue_entry size");

// ========= TSC 诊断（shared-queue 通道） =========
struct alignas(8) tsc_diag_snapshot {
  uint64_t seq;
  uint32_t cpu;
  uint32_t exit_reason;
  uint32_t hide_in;
  uint32_t reserved0;

  uint64_t guest_rip;

  uint64_t host_entry_tsc;
  uint64_t host_now_tsc;
  uint64_t elapsed;

  int64_t  tsc_offset_before;
  int64_t  tsc_offset_after;
  uint64_t last_guest_tsc;

  uint32_t cpuid_eax;
  uint32_t cpuid_ecx;
  uint64_t signature_rax;
};

struct alignas(8) tsc_diag_dump_header {
  uint64_t newest_seq;
  uint32_t count;
  uint32_t entry_size;
};

// ========= Exit statistics (shared-queue dump) =========
inline constexpr uint32_t exit_stats_version = 1;
inline constexpr uint32_t exit_stats_top_n   = 16;

struct alignas(8) exit_stats_msr_item {
  uint32_t msr;
  uint32_t _reserved;
  uint64_t count;
};

struct alignas(8) exit_stats_dump {
  uint32_t version;
  uint32_t cpu_count;

  // Per-VCPU TSC offset range (signed, cycles).
  int64_t  tsc_offset_min;
  int64_t  tsc_offset_max;

  uint64_t exit_total;
  uint64_t exit_cpuid;
  uint64_t exit_rdmsr;
  uint64_t exit_wrmsr;
  uint64_t exit_exception_or_nmi;
  uint64_t exit_nmi_window;
  uint64_t exit_preemption_timer;
  uint64_t exit_ept_violation;
  uint64_t exit_mov_cr;
  uint64_t exit_monitor_trap_flag;
  uint64_t exit_rdtsc;
  uint64_t exit_rdtscp;

  exit_stats_msr_item top_rdmsr[exit_stats_top_n];
  exit_stats_msr_item top_wrmsr[exit_stats_top_n];
};

inline shared_queue_header* sq_header(void* queue) {
  return reinterpret_cast<shared_queue_header*>(queue);
}

inline shared_queue_entry* sq_entries(void* queue) {
  return reinterpret_cast<shared_queue_entry*>(
    reinterpret_cast<uint8_t*>(queue) + sizeof(shared_queue_header));
}

enum class queue_register_status : uint32_t {
  success = 0,
  invalid_size,
  too_many_pages,
  translation_failed,
  registry_full,
};

struct queue_handshake_request {
  void*    queue;
  uint32_t size;
  uint64_t magic;
  uint64_t seed;
};

struct queue_handshake_raw_response {
  uint64_t rax;
  uint64_t rbx;
  uint64_t rcx;
  uint64_t rdx;
};

struct queue_handshake_result {
  uint64_t             signature;
  queue_register_status status;
  uint32_t             page_count;
  uint64_t             echoed_magic;
};

// hypercall input
struct hypercall_input {
  // rax
  struct {
    hypercall_code code : 8;
    uint64_t       key  : 56;
  };

  // rcx, rdx, r8, r9, r10, r11
  uint64_t args[6];
};

enum mmr_memory_mode {
  mmr_memory_mode_r = 0b001,
  mmr_memory_mode_w = 0b010,
  mmr_memory_mode_x = 0b100
};

// check if the system is virtualized
bool is_hv_running();

// call fn() on each logical processor
template <typename Fn>
void for_each_cpu(Fn fn);

// ping the hypervisor to make sure it is running (returns hypervisor_signature)
uint64_t ping();

// a hypercall for quick testing
uint64_t test(uint64_t a1 = 0, uint64_t a2 = 0,
              uint64_t a3 = 0, uint64_t a4 = 0,
              uint64_t a5 = 0, uint64_t a6 = 0);

// read from arbitrary physical memory
size_t read_phys_mem(void* dst, uint64_t src, size_t size);

// write to arbitrary physical memory
size_t write_phys_mem(uint64_t dst, void const* src, size_t size);

// read from virtual memory in another process
size_t read_virt_mem(uint64_t cr3, void* dst, void const* src, size_t size);

// write to virtual memory in another process
size_t write_virt_mem(uint64_t cr3, void* dst, void const* src, size_t size);

// get the kernel CR3 value of an arbitrary process
uint64_t query_process_cr3(uint64_t pid);

// install an EPT hook for the CURRENT logical processor ONLY
bool install_ept_hook(uint64_t orig_page_pfn, uint64_t exec_page_pfn);

// remove a previously installed EPT hook
void remove_ept_hook(uint64_t orig_page_pfn);

// flush the hypervisor logs into a buffer
void flush_logs(uint32_t& count, logger_msg* msgs);

// translate a virtual address to its physical address
uint64_t get_physical_address(uint64_t cr3, void const* address);

// hide a physical page from the guest
bool hide_physical_page(uint64_t pfn);

// unhide a physical page from the guest
void unhide_physical_page(uint64_t pfn);

// get the base address of the hypervisor
void* get_hv_base();

// write to the logger whenever a certain physical memory range is accessed
void* install_mmr(uint64_t address, uint32_t size, uint8_t mode);

// remove an existing MMR
void remove_mmr(void* handle);

// remove every installed MMR
void remove_all_mmrs();

// VMCALL instruction, defined in hv.asm
uint64_t vmx_vmcall(hypercall_input& input);

namespace detail {
inline uint64_t vmx_vmcall_safe(hypercall_input& input) {
  __try {
    return hv::vmx_vmcall(input);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return 0;
  }
}
} // namespace detail

// CPUID 握手，用于注册共享队列（定义在 hv.asm）
extern "C" void __fastcall hv_queue_handshake_asm(
  queue_handshake_request const* req,
  queue_handshake_raw_response*  resp);

inline queue_handshake_result queue_handshake(queue_handshake_request const& req) {
  queue_handshake_raw_response raw{};
  hv_queue_handshake_asm(&req, &raw);

  queue_handshake_result res{};
  res.signature   = raw.rax;
  res.status      = static_cast<queue_register_status>(raw.rbx);
  res.page_count  = static_cast<uint32_t>(raw.rcx);
  res.echoed_magic = raw.rdx;
  return res;
}

/**
* 
* implementation:
* 
**/

// check if the system is virtualized
inline bool is_hv_running() {
  __try {
    hv::queue_handshake_request req{};
    req.queue = nullptr;
    req.size  = 0;
    auto const res = hv::queue_handshake(req);
    return res.signature == hv::hypervisor_signature;
  } __except (1) {}

  return false;
}

// call fn() on each logical processor
template <typename Fn>
inline void for_each_cpu(Fn const fn) {
  SYSTEM_INFO info = {};
  GetSystemInfo(&info);

  for (uint32_t i = 0; i < info.dwNumberOfProcessors; ++i) {
    auto const prev_affinity = SetThreadAffinityMask(GetCurrentThread(), 1ull << i);
    fn(i);
    SetThreadAffinityMask(GetCurrentThread(), prev_affinity);
  }
}

// ping the hypervisor to make sure it is running (returns hypervisor_signature)
inline uint64_t ping() {
  hv::hypercall_input input;
  input.code = hv::hypercall_ping;
  input.key  = hv::hypercall_key;
  return hv::detail::vmx_vmcall_safe(input);
}

// a hypercall for quick testing
inline uint64_t test(uint64_t const a1, uint64_t const a2,
                     uint64_t const a3, uint64_t const a4,
                     uint64_t const a5, uint64_t const a6) {
  hv::hypercall_input input;
  input.code = hv::hypercall_test;
  input.key  = hv::hypercall_key;
  input.args[0] = a1;
  input.args[1] = a2;
  input.args[2] = a3;
  input.args[3] = a4;
  input.args[4] = a5;
  input.args[5] = a6;
  return hv::detail::vmx_vmcall_safe(input);
}

// devirtualize the CURRENT logical processor ONLY
inline void unload() {
  hv::hypercall_input input{};
  input.code = hv::hypercall_unload;
  input.key  = hv::hypercall_key;
  hv::detail::vmx_vmcall_safe(input);
}

// read from arbitrary physical memory
inline size_t read_phys_mem(void* const dst, uint64_t const src,
                            size_t const size) {
  hv::hypercall_input input;
  input.code    = hv::hypercall_read_phys_mem;
  input.key     = hv::hypercall_key;
  input.args[0] = reinterpret_cast<uint64_t>(dst);
  input.args[1] = src;
  input.args[2] = size;
  return hv::detail::vmx_vmcall_safe(input);
}

// write to arbitrary physical memory
inline size_t write_phys_mem(uint64_t const dst, void const* const src,
                             size_t const size) {
  hv::hypercall_input input;
  input.code    = hv::hypercall_write_phys_mem;
  input.key     = hv::hypercall_key;
  input.args[0] = dst;
  input.args[1] = reinterpret_cast<uint64_t>(src);
  input.args[2] = size;
  return hv::detail::vmx_vmcall_safe(input);
}

// read from virtual memory in another process
inline size_t read_virt_mem(uint64_t const cr3, void* const dst,
                            void const* const src, size_t const size) {
  hv::hypercall_input input;
  input.code    = hv::hypercall_read_virt_mem;
  input.key     = hv::hypercall_key;
  input.args[0] = cr3;
  input.args[1] = reinterpret_cast<uint64_t>(dst);
  input.args[2] = reinterpret_cast<uint64_t>(src);
  input.args[3] = size;
  return hv::detail::vmx_vmcall_safe(input);
}

// write to virtual memory in another process
inline size_t write_virt_mem(uint64_t const cr3, void* const dst,
                             void const* const src, size_t const size) {
  hv::hypercall_input input;
  input.code    = hv::hypercall_write_virt_mem;
  input.key     = hv::hypercall_key;
  input.args[0] = cr3;
  input.args[1] = reinterpret_cast<uint64_t>(dst);
  input.args[2] = reinterpret_cast<uint64_t>(src);
  input.args[3] = size;
  return hv::detail::vmx_vmcall_safe(input);
}

// get the kernel CR3 value of an arbitrary process
inline uint64_t query_process_cr3(uint64_t const pid) {
  hv::hypercall_input input;
  input.code    = hv::hypercall_query_process_cr3;
  input.key     = hv::hypercall_key;
  input.args[0] = pid;
  return hv::detail::vmx_vmcall_safe(input);
}

// install an EPT hook for the CURRENT logical processor ONLY
inline bool install_ept_hook(uint64_t const orig_page_pfn, uint64_t const exec_page_pfn) {
  hv::hypercall_input input;
  input.code    = hv::hypercall_install_ept_hook;
  input.key     = hv::hypercall_key;
  input.args[0] = orig_page_pfn;
  input.args[1] = exec_page_pfn;
  return hv::detail::vmx_vmcall_safe(input);
}

// remove a previously installed EPT hook
inline void remove_ept_hook(uint64_t const orig_page_pfn) {
  hv::hypercall_input input;
  input.code    = hv::hypercall_remove_ept_hook;
  input.key     = hv::hypercall_key;
  input.args[0] = orig_page_pfn;
  hv::detail::vmx_vmcall_safe(input);
}

// flush the hypervisor logs into a buffer
inline void flush_logs(uint32_t& count, logger_msg* const msgs) {
  hv::hypercall_input input;
  input.code    = hv::hypercall_flush_logs;
  input.key     = hv::hypercall_key;
  input.args[0] = count;
  input.args[1] = reinterpret_cast<uint64_t>(msgs);
  count = static_cast<uint32_t>(hv::detail::vmx_vmcall_safe(input));
}

// translate a virtual address to its physical address
inline uint64_t get_physical_address(uint64_t const cr3, void const* const address) {
  hv::hypercall_input input;
  input.code    = hv::hypercall_get_physical_address;
  input.key     = hv::hypercall_key;
  input.args[0] = cr3;
  input.args[1] = reinterpret_cast<uint64_t>(address);
  return hv::detail::vmx_vmcall_safe(input);
}

// hide a physical page from the guest
inline bool hide_physical_page(uint64_t const pfn) {
  hv::hypercall_input input;
  input.code    = hv::hypercall_hide_physical_page;
  input.key     = hv::hypercall_key;
  input.args[0] = pfn;
  return hv::detail::vmx_vmcall_safe(input);
}

// unhide a physical page from the guest
inline void unhide_physical_page(uint64_t const pfn) {
  hv::hypercall_input input;
  input.code    = hv::hypercall_unhide_physical_page;
  input.key     = hv::hypercall_key;
  input.args[0] = pfn;
  hv::detail::vmx_vmcall_safe(input);
}

// get the base address of the hypervisor
inline void* get_hv_base() {
  hv::hypercall_input input;
  input.code = hv::hypercall_get_hv_base;
  input.key  = hv::hypercall_key;
  return reinterpret_cast<void*>(hv::detail::vmx_vmcall_safe(input));
}

// write to the logger whenever a certain physical memory range is accessed
inline void* install_mmr(uint64_t const address, uint32_t const size,
                         uint8_t const mode) {
  hv::hypercall_input input;
  input.code    = hv::hypercall_install_mmr;
  input.key     = hv::hypercall_key;
  input.args[0] = address;
  input.args[1] = size;
  input.args[2] = mode;
  return reinterpret_cast<void*>(hv::detail::vmx_vmcall_safe(input));
}

// remove an existing MMR
inline void remove_mmr(void* const handle) {
  hv::hypercall_input input;
  input.code = hv::hypercall_remove_mmr;
  input.key  = hv::hypercall_key;
  input.args[0] = reinterpret_cast<uint64_t>(handle);
  hv::detail::vmx_vmcall_safe(input);
}

// remove every installed MMR
inline void remove_all_mmrs() {
  hv::hypercall_input input;
  input.code = hv::hypercall_remove_all_mmrs;
  input.key  = hv::hypercall_key;
  hv::detail::vmx_vmcall_safe(input);
}

} // namespace hv

