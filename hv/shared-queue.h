#pragma once

#include "mm.h"
#include "spin-lock.h"

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


