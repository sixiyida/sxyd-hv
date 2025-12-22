#include "shared-queue.h"

#include "logger.h"
#include "vcpu.h"
#include "vmx.h"
#include "page-tables.h"
#include "exception-routines.h"
#include "hv.h"
#include "ept.h"

namespace hv {

namespace {

spin_lock g_queue_lock = {};
shared_queue_context g_queue_entries[shared_queue_max_entries] = {};

} // namespace

shared_queue_register_result register_shared_queue(
  cr3 const guest_cr3, shared_queue_register_request const& req) {
  shared_queue_register_result result{};

  // 允许“注销/失效”操作：queue_size==0 视为对当前 CR3 的注销请求。
  // 这能让用户态在退出前显式解绑，避免 CR3/页复用导致的内存破坏。
  if (req.queue_size == 0) {
    invalidate_shared_queue(guest_cr3);
    result.status = shared_queue_status::success;
    result.page_count = 0;
    HV_LOG_INFO("[sq] deregister request: cr3=%p", guest_cr3.flags);
    return result;
  }

  if (!req.queue_size || req.queue_size > shared_queue_max_size) {
    result.status = shared_queue_status::invalid_size;
    HV_LOG_ERROR("[sq] invalid size: 0x%X (max=0x%X).", req.queue_size, shared_queue_max_size);
    return result;
  }

  auto const queue_va    = req.queue_gva;
  auto const page_offset = static_cast<uint64_t>(queue_va & 0xFFF);
  auto const total_size  = page_offset + req.queue_size;
  auto const page_count  = static_cast<uint32_t>((total_size + 0xFFF) >> 12);

  if (page_count == 0 || page_count > shared_queue_max_pages) {
    result.status = shared_queue_status::too_many_pages;
    HV_LOG_ERROR("[sq] too many pages: %u (limit=%u).", page_count, shared_queue_max_pages);
    return result;
  }

  uint64_t page_pfns[shared_queue_max_pages] = {};
  auto const base_page_va = queue_va & ~0xFFFull;

  for (uint32_t i = 0; i < page_count; ++i) {
    auto const page_gva = reinterpret_cast<void*>(base_page_va + (static_cast<uint64_t>(i) << 12));
    auto const gpa      = gva2gpa(guest_cr3, page_gva);
    if (!gpa) {
      result.status = shared_queue_status::translation_failed;
      HV_LOG_ERROR("[sq] gva2gpa failed for page #%u gva=%p cr3=%p.", i, page_gva, guest_cr3.flags);
      return result;
    }
    page_pfns[i] = gpa >> 12;
  }

  scoped_spin_lock lock(g_queue_lock);

  shared_queue_context* slot = nullptr;

  for (auto& entry : g_queue_entries) {
    if (entry.valid && entry.guest_cr3.flags == guest_cr3.flags) {
      slot = &entry;
      break;
    }
  }

  if (!slot) {
    for (auto& entry : g_queue_entries) {
      if (!entry.valid) {
        slot = &entry;
        break;
      }
    }
  }

  if (!slot) {
    result.status = shared_queue_status::registry_full;
    HV_LOG_ERROR("[sq] registry full.");
    return result;
  }

  slot->valid      = true;
  slot->guest_cr3  = guest_cr3;
  slot->queue_gva  = queue_va;
  slot->queue_size = req.queue_size;
  slot->magic      = req.magic;
  slot->seed       = req.seed;
  slot->page_count = page_count;

  memset(slot->page_pfns, 0, sizeof(slot->page_pfns));
  memcpy(slot->page_pfns, page_pfns, page_count * sizeof(page_pfns[0]));

  result.status     = shared_queue_status::success;
  result.page_count = page_count;
  HV_LOG_INFO("[sq] registered queue: cr3=%p gva=%p size=0x%X pages=%u magic=%p seed=%p",
    guest_cr3.flags, queue_va, req.queue_size, page_count, req.magic, req.seed);
  return result;
}

bool get_shared_queue_context(cr3 const guest_cr3, shared_queue_context* const out) {
  if (!out)
    return false;

  scoped_spin_lock lock(g_queue_lock);
  for (auto const& entry : g_queue_entries) {
    if (entry.valid && entry.guest_cr3.flags == guest_cr3.flags) {
      *out = entry; // 拷贝快照，避免锁外使用时被并发失效/覆盖
      return true;
    }
  }
  return false;
}

shared_queue_context const* find_shared_queue(cr3 const guest_cr3) {
  scoped_spin_lock lock(g_queue_lock);

  for (auto& entry : g_queue_entries) {
    if (entry.valid && entry.guest_cr3.flags == guest_cr3.flags)
      return &entry;
  }

  return nullptr;
}

void invalidate_shared_queue(cr3 const guest_cr3) {
  scoped_spin_lock lock(g_queue_lock);
  for (auto& entry : g_queue_entries) {
    if (entry.valid && entry.guest_cr3.flags == guest_cr3.flags) {
      entry.valid = false;
      HV_LOG_INFO("[sq] invalidated queue for cr3=%p", guest_cr3.flags);
      break;
    }
  }
}

void clear_all_shared_queues() {
  scoped_spin_lock lock(g_queue_lock);
  for (auto& entry : g_queue_entries)
    entry.valid = false;
  HV_LOG_INFO("[sq] cleared all queues.");
}

uint32_t process_shared_queue(vcpu* const cpu, bool* const has_pending) {
  if (!cpu)
    return 0;
  cr3 guest_cr3;
  guest_cr3.flags = vmx_vmread(VMCS_GUEST_CR3);

  shared_queue_context ctx{};
  if (!get_shared_queue_context(guest_cr3, &ctx))
    return 0;

  // 轻量一致性校验：如果队列所在第一页 PFN 与注册时不一致，说明映射/物理页已变化
  //（常见于用户态释放/重映射、CR3/页复用）。此时必须立即失效避免写坏随机内存。
  auto const base_page_va = ctx.queue_gva & ~0xFFFull;
  auto const base_gpa = gva2gpa(guest_cr3, reinterpret_cast<void*>(base_page_va), nullptr);
  if (!base_gpa || (base_gpa >> 12) != ctx.page_pfns[0]) {
    HV_LOG_ERROR("[sq] queue page changed: cr3=%p gva=%p old_pfn=%p new_gpa=%p",
      guest_cr3.flags, ctx.queue_gva, ctx.page_pfns[0], base_gpa);
    invalidate_shared_queue(guest_cr3);
    return 0;
  }

  size_t header_remaining = 0;
  auto* header = reinterpret_cast<shared_queue_header*>(
    gva2hva(guest_cr3, reinterpret_cast<void*>(ctx.queue_gva), &header_remaining));

  if (!header || header_remaining < sizeof(shared_queue_header)) {
    HV_LOG_ERROR("[sq] header translation failed: gva=%p cr3=%p", ctx.queue_gva, guest_cr3.flags);
    invalidate_shared_queue(guest_cr3);
    return 0;
  }

  auto const capacity = (ctx.queue_size > sizeof(shared_queue_header))
    ? static_cast<uint32_t>((ctx.queue_size - sizeof(shared_queue_header)) / sizeof(shared_queue_entry))
    : 0;

  if (capacity == 0)
    return 0;

  auto head = header->head;
  auto tail = header->tail;

  if (has_pending)
    *has_pending = (head != tail);

  uint32_t processed = 0;
  constexpr uint32_t max_batch = 4;

  while (tail != head && processed < max_batch) {
    auto const idx = tail % capacity;
    auto const entry_gva = ctx.queue_gva + sizeof(shared_queue_header)
      + static_cast<uint64_t>(idx) * sizeof(shared_queue_entry);

    size_t entry_remaining = 0;
    auto* entry = reinterpret_cast<shared_queue_entry*>(
      gva2hva(guest_cr3, reinterpret_cast<void*>(entry_gva), &entry_remaining));

    if (!entry || entry_remaining < sizeof(shared_queue_entry)) {
      HV_LOG_ERROR("[sq] entry translate failed: gva=%p idx=%u cr3=%p",
        entry_gva, idx, guest_cr3.flags);
      tail++;
      processed++;
      continue;
    }

    switch (static_cast<shared_queue_cmd>(entry->cmd)) {
    case shared_queue_cmd::nop:
      entry->status = static_cast<uint32_t>(shared_queue_entry_status::done);
      break;

    case shared_queue_cmd::read_phys: {
      auto const gpa  = entry->gpa;
      auto const size = static_cast<size_t>(entry->size);
      auto* const dst = reinterpret_cast<uint8_t*>(entry->gva);

      size_t copied = 0;
      while (copied < size) {
        size_t dst_remaining = 0;
        auto* curr_dst = reinterpret_cast<uint8_t*>(
          gva2hva(guest_cr3, dst + copied, &dst_remaining));
        if (!curr_dst) {
          entry->status = static_cast<uint32_t>(shared_queue_entry_status::err_translate);
          goto done_entry;
        }
        size_t const curr_size = (dst_remaining < (size - copied))
          ? dst_remaining
          : (size - copied);
        host_exception_info e;
        memcpy_safe(e, curr_dst, host_physical_memory_base + gpa + copied, curr_size);
        if (e.exception_occurred) {
          entry->status = static_cast<uint32_t>(shared_queue_entry_status::err_translate);
          goto done_entry;
        }
        copied += curr_size;
      }
      entry->aux    = size;
      entry->status = static_cast<uint32_t>(shared_queue_entry_status::done);
    } break;

    case shared_queue_cmd::write_phys: {
      auto const gpa  = entry->gpa;
      auto const size = static_cast<size_t>(entry->size);
      auto const* src = reinterpret_cast<uint8_t const*>(entry->gva);

      size_t copied = 0;
      while (copied < size) {
        size_t src_remaining = 0;
        auto const* curr_src = reinterpret_cast<uint8_t const*>(
          gva2hva(guest_cr3, const_cast<uint8_t*>(src + copied), &src_remaining));
        if (!curr_src) {
          entry->status = static_cast<uint32_t>(shared_queue_entry_status::err_translate);
          goto done_entry;
        }
        size_t const curr_size = (src_remaining < (size - copied))
          ? src_remaining
          : (size - copied);
        host_exception_info e;
        memcpy_safe(e, host_physical_memory_base + gpa + copied, curr_src, curr_size);
        if (e.exception_occurred) {
          entry->status = static_cast<uint32_t>(shared_queue_entry_status::err_translate);
          goto done_entry;
        }
        copied += curr_size;
      }
      entry->aux    = size;
      entry->status = static_cast<uint32_t>(shared_queue_entry_status::done);
    } break;

    case shared_queue_cmd::read_virt: {
      cr3 target_cr3;
      target_cr3.flags = entry->cr3 ? entry->cr3 : guest_cr3.flags;

      auto const* src = reinterpret_cast<uint8_t const*>(entry->gva); // 源 VA（目标 CR3）
      auto* const dst = reinterpret_cast<uint8_t*>(entry->gpa);       // 目的 VA（当前进程）
      auto const size = static_cast<size_t>(entry->size);

      size_t copied = 0;
      while (copied < size) {
        size_t dst_remaining = 0, src_remaining = 0;
        auto* curr_dst = reinterpret_cast<uint8_t*>(
          gva2hva(guest_cr3, dst + copied, &dst_remaining));
        auto const* curr_src = reinterpret_cast<uint8_t const*>(
          gva2hva(target_cr3, const_cast<uint8_t*>(src + copied), &src_remaining));

        if (!curr_dst || !curr_src) {
          entry->status = static_cast<uint32_t>(shared_queue_entry_status::err_translate);
          goto done_entry;
        }

        size_t curr_size = (dst_remaining < (size - copied))
          ? dst_remaining
          : (size - copied);
        if (curr_size > src_remaining)
          curr_size = src_remaining;

        host_exception_info e;
        memcpy_safe(e, curr_dst, curr_src, curr_size);
        if (e.exception_occurred) {
          entry->status = static_cast<uint32_t>(shared_queue_entry_status::err_translate);
          goto done_entry;
        }
        copied += curr_size;
      }
      entry->aux    = size;
      entry->status = static_cast<uint32_t>(shared_queue_entry_status::done);
    } break;

    case shared_queue_cmd::write_virt: {
      cr3 target_cr3;
      target_cr3.flags = entry->cr3 ? entry->cr3 : guest_cr3.flags;

      auto const* src = reinterpret_cast<uint8_t const*>(entry->gpa); // 源 VA（当前进程）
      auto* const dst = reinterpret_cast<uint8_t*>(entry->gva);       // 目的 VA（目标 CR3）
      auto const size = static_cast<size_t>(entry->size);

      size_t copied = 0;
      while (copied < size) {
        size_t dst_remaining = 0, src_remaining = 0;
        auto* curr_dst = reinterpret_cast<uint8_t*>(
          gva2hva(target_cr3, dst + copied, &dst_remaining));
        auto const* curr_src = reinterpret_cast<uint8_t const*>(
          gva2hva(guest_cr3, const_cast<uint8_t*>(src + copied), &src_remaining));

        if (!curr_dst || !curr_src) {
          entry->status = static_cast<uint32_t>(shared_queue_entry_status::err_translate);
          goto done_entry;
        }

        size_t curr_size = (dst_remaining < (size - copied))
          ? dst_remaining
          : (size - copied);
        if (curr_size > src_remaining)
          curr_size = src_remaining;

        host_exception_info e;
        memcpy_safe(e, curr_dst, curr_src, curr_size);
        if (e.exception_occurred) {
          entry->status = static_cast<uint32_t>(shared_queue_entry_status::err_translate);
          goto done_entry;
        }
        copied += curr_size;
      }
      entry->aux    = size;
      entry->status = static_cast<uint32_t>(shared_queue_entry_status::done);
    } break;

    case shared_queue_cmd::query_ept_map: {
      // Input:
      //   entry->cr3 : target CR3 (0 => current guest cr3)
      //   entry->gva : guest virtual address to query
      // Output:
      //   entry->gpa      = original PFN (gpa >> 12)
      //   entry->aux      = mapped PFN in EPT
      //   entry->reserved = dummy PFN (for comparison)
      cr3 target_cr3;
      target_cr3.flags = entry->cr3 ? entry->cr3 : guest_cr3.flags;

      auto const gpa = gva2gpa(target_cr3, reinterpret_cast<void*>(entry->gva), nullptr);
      if (!gpa) {
        entry->status = static_cast<uint32_t>(shared_queue_entry_status::err_translate);
        goto done_entry;
      }

      auto const pte = get_ept_pte(cpu->ept, gpa, false);
      if (!pte) {
        entry->status = static_cast<uint32_t>(shared_queue_entry_status::err_translate);
        goto done_entry;
      }

      entry->gpa      = (gpa >> 12);
      entry->aux      = pte->page_frame_number;
      entry->reserved = cpu->ept.dummy_page_pfn;
      entry->status   = static_cast<uint32_t>(shared_queue_entry_status::done);
    } break;

    default:
      entry->status = static_cast<uint32_t>(shared_queue_entry_status::err_unimplemented);
      break;
    }

done_entry:
    HV_LOG_INFO("[sq] processed idx=%u cmd=%u status=%u cr3=%p gva=%p gpa=%p size=0x%X",
      idx,
      entry->cmd,
      entry->status,
      entry->cr3,
      entry->gva,
      entry->gpa,
      entry->size);

    tail++;
    processed++;
  }

  header->tail = tail;
  return processed;
}

} // namespace hv


