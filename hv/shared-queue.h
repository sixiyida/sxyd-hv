#pragma once

#include "mm.h"
#include "spin-lock.h"
#include <stdint.h>

namespace hv {

struct vcpu;

// CPUID 握手（使用标准扩展叶，避免异常 Leaf 特征）
inline constexpr uint32_t shared_queue_cpuid_leaf               = 0x80000000;
inline constexpr uint32_t shared_queue_magic0                  = 0x9D2F'4B1Au; // 输入 RCX
inline constexpr uint32_t shared_queue_magic1                  = 0xC3E1'5A7Bu; // 输入 RSI
inline constexpr uint32_t shared_queue_cpuid_subleaf_handshake = 0;            // 仍固定 0

// 资源上限
inline constexpr uint32_t shared_queue_max_size     = 0x200000; // 2 MiB 防御过大映射
inline constexpr uint32_t shared_queue_max_pages    = 64;
inline constexpr uint32_t shared_queue_max_entries  = 64;

// ========= TSC 诊断（通过 shared-queue 拉取，无需 hypercall） =========
#if !defined(HV_TSC_DIAG)
#define HV_TSC_DIAG 1
#endif
#if !defined(HV_TSC_DIAG_RING_SIZE)
#define HV_TSC_DIAG_RING_SIZE 1024u
#endif
#if !defined(HV_TSC_DIAG_RATE)
#define HV_TSC_DIAG_RATE 512u
#endif
#if !defined(HV_TSC_DIAG_ELAPSED_THRESH)
#define HV_TSC_DIAG_ELAPSED_THRESH 50000ull
#endif

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

// 记录一条诊断快照到 ring buffer。
void tsc_diag_record(tsc_diag_snapshot const& snap);

// 把最近的快照拷到 dst（dst 为 guest 映射缓冲），返回写入条数。
uint32_t tsc_diag_dump(void* dst, uint32_t dst_bytes, uint64_t* newest_seq_out);

// 握手状态码
enum class shared_queue_status : uint32_t {
  success = 0,
  invalid_size,
  too_many_pages,
  translation_failed,
  registry_full,
};

// 队列条目命令与状态
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

  // Per-VCPU TSC offset range (signed, cycles). Useful to diagnose time drift/jitter.
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

enum class shared_queue_entry_status : uint32_t {
  pending           = 0,
  done              = 1,
  err_unimplemented = 0x80000001,
  err_translate     = 0x80000002,
};

// 队列头部（位于队列起始处）
struct shared_queue_header {
  uint32_t head;
  uint32_t tail;
  uint32_t reserved0;
  uint32_t reserved1;
};

// 队列条目（对齐 64 字节，方便 cacheline）
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

// 队列上下文（后续轮询使用）
struct shared_queue_context {
  bool     valid;
  cr3      guest_cr3;
  uint64_t queue_gva;
  uint32_t queue_size;
  uint64_t magic;
  uint64_t seed;
  uint32_t page_count;
  uint64_t page_pfns[shared_queue_max_pages]; // guest PFN（gpa >> 12）
};

struct shared_queue_register_request {
  uint64_t queue_gva;
  uint32_t queue_size;
  uint64_t magic;
  uint64_t seed;
};

struct shared_queue_register_result {
  shared_queue_status status;
  uint32_t            page_count;
};

// 复制一个已注册队列的上下文（按 CR3）。返回 true 表示找到且 out 已填充。
bool get_shared_queue_context(cr3 guest_cr3, shared_queue_context* out);

// 注册共享队列（CPUID 握手）
shared_queue_register_result register_shared_queue(
  cr3 guest_cr3, shared_queue_register_request const& req);

// 查找已注册队列（按 CR3）
shared_queue_context const* find_shared_queue(cr3 guest_cr3);

// 失效某个已注册队列（按 CR3）
void invalidate_shared_queue(cr3 guest_cr3);

// 清空所有已注册队列（用于 stop/unload）
void clear_all_shared_queues();

// 处理共享队列（在 VMX preemption timer 等处调用），返回已处理条目数
// 可选输出：has_pending 表示是否检测到 head!=tail（仍有待处理或有队列存在）
uint32_t process_shared_queue(vcpu* cpu, bool* has_pending = nullptr);

} // namespace hv


