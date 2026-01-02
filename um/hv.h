#pragma once

#include <cstddef>
#include <cstdint>
#include <intrin.h>
#include <Windows.h>

namespace hv {

// signature that is returned by the CPUID handshake
inline constexpr uint64_t hypervisor_signature = 'fr0g';

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
  // debug: query EPT mapping for a guest physical address (returns PFNs)
  query_ept_gpa,
  // debug: query whether a PFN is EPT-hooked, and return hook read/exec PFNs
  query_ept_hook_gpa,
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

// A clean UM-side shared-queue session:
// - explicitly owns a queue buffer (VirtualAlloc)
// - registers via CPUID handshake
// - submits commands by writing entries and "kicking" via CPUID to trigger a VM-exit
class shared_queue_session {
public:
  static constexpr size_t   default_queue_size = 0x2000; // 2 pages
  static constexpr uint64_t default_magic      = 0xC0FFEE123456789ull;
  static constexpr uint64_t default_seed       = 0xBADF00DCAFEBABEull;

  shared_queue_session() = default;

  shared_queue_session(size_t const queue_size, uint64_t const magic, uint64_t const seed) {
    (void)open(queue_size, magic, seed);
  }

  shared_queue_session(shared_queue_session const&) = delete;
  shared_queue_session& operator=(shared_queue_session const&) = delete;

  ~shared_queue_session() { close(); }

  bool open(size_t const queue_size = default_queue_size,
            uint64_t const magic = default_magic,
            uint64_t const seed = default_seed) {
    if (registered_)
      return true;

    queue_size_ = queue_size ? queue_size : default_queue_size;
    queue_ = static_cast<uint8_t*>(
      VirtualAlloc(nullptr, queue_size_, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

    if (!queue_) {
      queue_size_ = 0;
      return false;
    }

    // Best-effort: keep pages resident to reduce translation failures.
    (void)VirtualLock(queue_, queue_size_);

    ZeroMemory(queue_, queue_size_);

    req_ = {};
    req_.queue = queue_;
    req_.size  = static_cast<uint32_t>(queue_size_);
    req_.magic = magic;
    req_.seed  = seed;

    last_hs_ = {};
    __try {
      last_hs_ = queue_handshake(req_);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      last_hs_.signature = 0;
      last_hs_.status = static_cast<queue_register_status>(0xFFFF'FFFFu);
      last_hs_.page_count = 0;
      last_hs_.echoed_magic = 0;
    }

    if (last_hs_.signature != hypervisor_signature ||
        last_hs_.status != queue_register_status::success) {
      close();
      return false;
    }

    registered_ = true;
    return true;
  }

  void close() {
    if (!queue_ || !queue_size_)
      return;

    if (registered_) {
      queue_handshake_request dereg{};
      dereg.queue = nullptr;
      dereg.size  = 0;
      dereg.magic = req_.magic;
      dereg.seed  = req_.seed;
      __try { (void)queue_handshake(dereg); } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    VirtualUnlock(queue_, queue_size_);
    VirtualFree(queue_, 0, MEM_RELEASE);

    queue_ = nullptr;
    queue_size_ = 0;
    registered_ = false;
    req_ = {};
    last_hs_ = {};
  }

  [[nodiscard]] bool ok() const { return registered_; }
  [[nodiscard]] queue_handshake_result last_handshake() const { return last_hs_; }
  [[nodiscard]] void* raw_queue() const { return queue_; }
  [[nodiscard]] shared_queue_header* header() const { return queue_ ? sq_header(queue_) : nullptr; }
  [[nodiscard]] shared_queue_entry* entries() const { return queue_ ? sq_entries(queue_) : nullptr; }

  // Submit a single entry (idx=0) and wait for completion.
  // On success, in_out is replaced with the completed entry (status/aux/reserved filled by HV).
  bool submit(shared_queue_entry& in_out, uint32_t timeout_ms = 2000) {
    if (!registered_ && !open())
      return false;

    auto* const qhdr = header();
    auto* const qent = entries();
    if (!qhdr || !qent)
      return false;

    qhdr->head = 0;
    qhdr->tail = 0;
    ZeroMemory(&qent[0], sizeof(shared_queue_entry));

    qent[0] = in_out;
    qent[0].status = static_cast<uint32_t>(shared_queue_entry_status::pending);

    _mm_mfence();
    qhdr->head = 1;
    _mm_mfence();

    kick_vmexit();

    DWORD waited = 0;
    while (waited < timeout_ms) {
      auto const st = qent[0].status;
      if (st != static_cast<uint32_t>(shared_queue_entry_status::pending))
        break;

      if ((waited % 50) == 0)
        kick_vmexit();

      Sleep(10);
      waited += 10;
    }

    in_out = qent[0];
    return in_out.status == static_cast<uint32_t>(shared_queue_entry_status::done);
  }

  // Convenience ops (shared-queue semantics, no legacy hypercall compatibility):
  size_t read_physical(void* dst, uint64_t gpa, size_t size, uint32_t timeout_ms = 2000) {
    if (size == 0 || size > 0xFFFF'FFFFull)
      return 0;
    shared_queue_entry e{};
    e.cmd  = static_cast<uint32_t>(shared_queue_cmd::read_phys);
    e.gva  = reinterpret_cast<uint64_t>(dst);
    e.gpa  = gpa;
    e.size = static_cast<uint32_t>(size);
    if (!submit(e, timeout_ms))
      return 0;
    return static_cast<size_t>(e.aux);
  }

  size_t write_physical(uint64_t gpa, void const* src, size_t size, uint32_t timeout_ms = 2000) {
    if (size == 0 || size > 0xFFFF'FFFFull)
      return 0;
    shared_queue_entry e{};
    e.cmd  = static_cast<uint32_t>(shared_queue_cmd::write_phys);
    e.gva  = reinterpret_cast<uint64_t>(src);
    e.gpa  = gpa;
    e.size = static_cast<uint32_t>(size);
    if (!submit(e, timeout_ms))
      return 0;
    return static_cast<size_t>(e.aux);
  }

  // Read virtual memory from target CR3 into current-process dst buffer.
  // If target_cr3==0, HV uses current guest CR3.
  size_t read_virtual(uint64_t target_cr3, void* dst, void const* src, size_t size, uint32_t timeout_ms = 2000) {
    if (size == 0 || size > 0xFFFF'FFFFull)
      return 0;
    shared_queue_entry e{};
    e.cmd  = static_cast<uint32_t>(shared_queue_cmd::read_virt);
    e.cr3  = target_cr3;
    e.gva  = reinterpret_cast<uint64_t>(src); // src VA (target CR3)
    e.gpa  = reinterpret_cast<uint64_t>(dst); // dst VA (current process)
    e.size = static_cast<uint32_t>(size);
    if (!submit(e, timeout_ms))
      return 0;
    return static_cast<size_t>(e.aux);
  }

  // Write virtual memory from current-process src buffer into target CR3 dst VA.
  size_t write_virtual(uint64_t target_cr3, void* dst, void const* src, size_t size, uint32_t timeout_ms = 2000) {
    if (size == 0 || size > 0xFFFF'FFFFull)
      return 0;
    shared_queue_entry e{};
    e.cmd  = static_cast<uint32_t>(shared_queue_cmd::write_virt);
    e.cr3  = target_cr3;
    e.gva  = reinterpret_cast<uint64_t>(dst); // dst VA (target CR3)
    e.gpa  = reinterpret_cast<uint64_t>(src); // src VA (current process)
    e.size = static_cast<uint32_t>(size);
    if (!submit(e, timeout_ms))
      return 0;
    return static_cast<size_t>(e.aux);
  }

private:
  static void kick_vmexit() {
    int regs[4] = {};
    __cpuid(regs, 0);
  }

  uint8_t*               queue_      = nullptr;
  size_t                 queue_size_ = 0;
  queue_handshake_request req_{};
  queue_handshake_result  last_hs_{};
  bool                   registered_ = false;
};

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

// ping the hypervisor to make sure it is running (returns hypervisor_signature)
inline uint64_t ping() {
  hv::queue_handshake_request req{};
  req.queue = nullptr;
  req.size  = 0;
  __try {
    auto const res = hv::queue_handshake(req);
    return res.signature;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return 0;
  }
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

} // namespace hv

