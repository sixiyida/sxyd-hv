#include "shared-queue.h"

#include "logger.h"
#include "vcpu.h"
#include "vmx.h"
#include "page-tables.h"
#include "exception-routines.h"
#include "hv.h"
#include "ept.h"
#include "mm.h"

namespace hv {

namespace {

spin_lock g_queue_lock = {};
shared_queue_context g_queue_entries[shared_queue_max_entries] = {};

#if HV_TSC_DIAG
// TSC 诊断 ring buffer（只用于调试/定位，不用于功能正确性）
static volatile LONG64 g_tsc_diag_seq = 0;
static tsc_diag_snapshot g_tsc_diag_ring[HV_TSC_DIAG_RING_SIZE] = {};
#endif

} // namespace

#if 1
// Update EPT mapping for shared-queue pages:
// - If the currently running CR3 owns a registered queue: ensure those PFNs are identity-mapped in EPT (visible).
// - Otherwise: ensure the previously-visible queue PFNs are remapped to dummy_page (hidden).
//
// Why this works:
// - Guest accesses go through EPT, so remapping hides the real page contents from other contexts.
// - Root-mode queue processing uses host_physical_memory_base + GPA, which does NOT go through EPT.
//
// Limitations:
// - Best-effort only. If a queue is deregistered and its PFNs get reused, we avoid acting on stale PFNs by
//   re-querying the registry before hiding/unhiding.
void update_shared_queue_ept_hide(vcpu* const cpu) {
  if (!cpu)
    return;

  // Global kill-switch (default off).
  if (!ghv.sq_hide_enabled)
    return;

  cr3 guest_cr3;
  guest_cr3.flags = vmx_vmread(VMCS_GUEST_CR3);

  // Avoid doing work on every VM-exit unless CR3 changed or forced.
  if (!cpu->sq_ept_force_update && cpu->sq_ept_last_guest_cr3 == guest_cr3.flags)
    return;

  cpu->sq_ept_last_guest_cr3 = guest_cr3.flags;
  cpu->sq_ept_force_update = false;

  // Determine if there is an active queue for the CURRENT CR3.
  shared_queue_context cur_ctx{};
  bool cur_has_queue = get_shared_queue_context(guest_cr3, &cur_ctx);

  auto validate_ctx_pfns = [&](cr3 const target_cr3, shared_queue_context const& ctx) -> bool {
    // Validate that the registered PFNs still match the current guest page tables for that CR3.
    // This is critical because EPT remaps PFNs globally: if the queue pages were freed and the
    // physical pages got reused for unrelated kernel/user allocations, keeping them mapped to
    // dummy_page would corrupt random memory and can crash the system (e.g. lsass).
    auto const base_page_va = ctx.queue_gva & ~0xFFFull;
    for (uint32_t i = 0; i < ctx.page_count; ++i) {
      auto const page_gva = reinterpret_cast<void*>(base_page_va + (static_cast<uint64_t>(i) << 12));
      auto const gpa = gva2gpa(target_cr3, page_gva, nullptr);
      if (!gpa)
        return false;
      if ((gpa >> 12) != ctx.page_pfns[i])
        return false;
    }
    return true;
  };

  // If the current CR3 claims to own a queue but the PFNs no longer match, invalidate it and
  // restore identity mapping for the stale PFNs (best-effort safety).
  if (cur_has_queue && !validate_ctx_pfns(guest_cr3, cur_ctx)) {
    __try {
      unhide_pfns_in_ept(cpu->ept, cur_ctx.page_pfns, cur_ctx.page_count);
    } __except (1) {}
    invalidate_shared_queue(guest_cr3);
    cur_has_queue = false;
  }

  // If we previously had a visible queue, and we're no longer in that CR3 (or it no longer has a queue),
  // re-hide it (if it still exists in the registry).
  if (cpu->sq_ept_visible_cr3) {
    cr3 prev_cr3;
    prev_cr3.flags = cpu->sq_ept_visible_cr3;

    if (prev_cr3.flags != guest_cr3.flags || !cur_has_queue) {
      shared_queue_context prev_ctx{};
      if (get_shared_queue_context(prev_cr3, &prev_ctx)) {
        // Validate before applying any EPT remap to avoid poisoning reused physical pages.
        if (!validate_ctx_pfns(prev_cr3, prev_ctx)) {
          __try {
            unhide_pfns_in_ept(cpu->ept, prev_ctx.page_pfns, prev_ctx.page_count);
          } __except (1) {}
          invalidate_shared_queue(prev_cr3);
        } else {
        __try {
          hide_pfns_in_ept(cpu->ept, prev_ctx.page_pfns, prev_ctx.page_count);
          // hide_pfns_in_ept() does not flush; do it here.
          vmx_invept(invept_all_context, {});
        } __except (1) {
          // best-effort: ignore
        }
        }
      }

      cpu->sq_ept_visible_cr3 = 0;
    }
  }

  // If current CR3 owns a queue, ensure it's visible in EPT.
  if (cur_has_queue) {
    __try {
      unhide_pfns_in_ept(cpu->ept, cur_ctx.page_pfns, cur_ctx.page_count);
      cpu->sq_ept_visible_cr3 = guest_cr3.flags;
    } __except (1) {
      // best-effort
      cpu->sq_ept_visible_cr3 = 0;
    }
  }
}
#endif

#if 1
static void exit_stats_build_msr_top(
    exit_stats_msr_item (&out_top)[exit_stats_top_n],
    bool const is_rdmsr) {
  // temp hash table to merge counts across CPUs (best-effort)
  struct alignas(8) tmp_slot {
    uint32_t msr;
    uint32_t _reserved;
    uint64_t count;
  };
  constexpr uint32_t tmp_size = 256; // power-of-two
  constexpr uint32_t tmp_mask = tmp_size - 1;
  constexpr uint32_t sentinel = diag_msr_sentinel;

  tmp_slot tmp[tmp_size] = {};
  for (auto& s : tmp) {
    s.msr = sentinel;
    s.count = 0;
  }

  auto tmp_add = [&](uint32_t const msr, uint64_t const add) {
    if (msr == sentinel || add == 0)
      return;
    uint32_t idx = (msr * 2654435761u) & tmp_mask;
    for (uint32_t probe = 0; probe < tmp_size; ++probe) {
      auto& slot = tmp[(idx + probe) & tmp_mask];
      if (slot.msr == msr) {
        slot.count += add;
        return;
      }
      if (slot.msr == sentinel) {
        slot.msr = msr;
        slot.count = add;
        return;
      }
    }
  };

  // Merge all VCPU tables.
  if (ghv.vcpus && ghv.vcpu_count) {
    for (unsigned long i = 0; i < ghv.vcpu_count; ++i) {
      auto const& cpu = ghv.vcpus[i];
      auto const* table = is_rdmsr ? cpu.diag_rdmsr_msrs : cpu.diag_wrmsr_msrs;
      for (uint32_t j = 0; j < diag_msr_table_size; ++j) {
        auto const msr = table[j].msr;
        auto const cnt = table[j].count;
        if (msr == sentinel || cnt == 0)
          continue;
        tmp_add(msr, cnt);
      }
    }
  }

  // Extract top-N.
  for (uint32_t k = 0; k < exit_stats_top_n; ++k) {
    uint32_t best_idx = 0xFFFFFFFFu;
    uint64_t best_cnt = 0;
    for (uint32_t i = 0; i < tmp_size; ++i) {
      if (tmp[i].msr == sentinel || tmp[i].count == 0)
        continue;
      if (tmp[i].count > best_cnt) {
        best_cnt = tmp[i].count;
        best_idx = i;
      }
    }

    if (best_idx == 0xFFFFFFFFu)
      break;

    out_top[k].msr = tmp[best_idx].msr;
    out_top[k].count = tmp[best_idx].count;

    tmp[best_idx].msr = sentinel;
    tmp[best_idx].count = 0;
  }
}

static void exit_stats_build(exit_stats_dump& out) {
  out = {};
  out.version = exit_stats_version;
  out.cpu_count = ghv.vcpu_count;
  out.tsc_offset_min = 0;
  out.tsc_offset_max = 0;

  if (ghv.vcpus && ghv.vcpu_count) {
    bool first = true;
    for (unsigned long i = 0; i < ghv.vcpu_count; ++i) {
      auto const& cpu = ghv.vcpus[i];
      auto const off_s = static_cast<int64_t>(cpu.tsc_offset);
      if (first) {
        out.tsc_offset_min = off_s;
        out.tsc_offset_max = off_s;
        first = false;
      } else {
        if (off_s < out.tsc_offset_min) out.tsc_offset_min = off_s;
        if (off_s > out.tsc_offset_max) out.tsc_offset_max = off_s;
      }
      out.exit_total            += cpu.diag_exit_total;
      out.exit_cpuid            += cpu.diag_exit_cpuid;
      out.exit_rdmsr            += cpu.diag_exit_rdmsr;
      out.exit_wrmsr            += cpu.diag_exit_wrmsr;
      out.exit_exception_or_nmi += cpu.diag_exit_exception_or_nmi;
      out.exit_nmi_window       += cpu.diag_exit_nmi_window;
      out.exit_preemption_timer += cpu.diag_exit_preemption_timer;
      out.exit_ept_violation    += cpu.diag_exit_ept_violation;
      out.exit_mov_cr           += cpu.diag_exit_mov_cr;
      out.exit_monitor_trap_flag+= cpu.diag_exit_monitor_trap_flag;
      out.exit_rdtsc            += cpu.diag_exit_rdtsc;
      out.exit_rdtscp           += cpu.diag_exit_rdtscp;
    }
  }

  exit_stats_build_msr_top(out.top_rdmsr, true);
  exit_stats_build_msr_top(out.top_wrmsr, false);
}
#endif

#if HV_TSC_DIAG
void tsc_diag_record(tsc_diag_snapshot const& snap) {
  auto const seq = static_cast<uint64_t>(InterlockedIncrement64(&g_tsc_diag_seq));
  auto const idx = static_cast<uint32_t>(seq % static_cast<uint64_t>(HV_TSC_DIAG_RING_SIZE));

  auto s = snap;
  s.seq = seq;
  g_tsc_diag_ring[idx] = s;
}

uint32_t tsc_diag_dump(void* const dst, uint32_t const dst_bytes, uint64_t* const newest_seq_out) {
  if (!dst || dst_bytes < sizeof(tsc_diag_dump_header))
    return 0;

  auto const newest = static_cast<uint64_t>(InterlockedCompareExchange64(&g_tsc_diag_seq, 0, 0));
  if (newest_seq_out)
    *newest_seq_out = newest;

  auto* const hdr = reinterpret_cast<tsc_diag_dump_header*>(dst);
  hdr->newest_seq = newest;
  hdr->entry_size = sizeof(tsc_diag_snapshot);

  auto const max_entries = (dst_bytes - sizeof(tsc_diag_dump_header)) / sizeof(tsc_diag_snapshot);
  uint32_t const count = (newest < max_entries) ? static_cast<uint32_t>(newest) : static_cast<uint32_t>(max_entries);
  hdr->count = count;

  auto* const out = reinterpret_cast<tsc_diag_snapshot*>(
    reinterpret_cast<uint8_t*>(dst) + sizeof(tsc_diag_dump_header));

  // newest-first
  for (uint32_t i = 0; i < count; ++i) {
    auto const seq = newest - i;
    auto const idx = static_cast<uint32_t>(seq % static_cast<uint64_t>(HV_TSC_DIAG_RING_SIZE));
    out[i] = g_tsc_diag_ring[idx];
  }

  return count;
}
#else
void tsc_diag_record(tsc_diag_snapshot const&) {}
uint32_t tsc_diag_dump(void*, uint32_t, uint64_t*) { return 0; }
#endif

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

    case shared_queue_cmd::query_ept_gpa: {
      // Input:
      //   entry->gpa : guest physical address to query
      // Output:
      //   entry->gpa      = original PFN (gpa >> 12)
      //   entry->aux      = mapped PFN in EPT (for this VCPU's EPT)
      //   entry->reserved = dummy PFN (for comparison)
      auto const gpa = entry->gpa;
      if (!gpa) {
        entry->status = static_cast<uint32_t>(shared_queue_entry_status::err_translate);
        goto done_entry;
      }

      uint64_t mapped_pfn = 0;

      if (auto const pte = get_ept_pte(cpu->ept, gpa, false)) {
        mapped_pfn = pte->page_frame_number;
      } else {
        // If the mapping is still a 2MB large page, derive the PFN from the PDE.
        // NOTE: if the PDE is already split, get_ept_pte() should have succeeded above.
        pml4_virtual_address const addr = { reinterpret_cast<void*>(gpa) };
        if (addr.pml4_idx == 0 && addr.pdpt_idx < ept_pd_count) {
          auto const& pde2 = cpu->ept.pds_2mb[addr.pdpt_idx][addr.pd_idx];
          if (pde2.large_page) {
            mapped_pfn = (pde2.page_frame_number << 9) + addr.pt_idx;
          }
        }
      }

      if (!mapped_pfn) {
        entry->status = static_cast<uint32_t>(shared_queue_entry_status::err_translate);
        goto done_entry;
      }

      entry->gpa      = (gpa >> 12);
      entry->aux      = mapped_pfn;
      entry->reserved = cpu->ept.dummy_page_pfn;
      entry->status   = static_cast<uint32_t>(shared_queue_entry_status::done);
    } break;

    case shared_queue_cmd::query_ept_hook_gpa: {
      // Input:
      //   entry->gpa : guest physical address to query (we key hooks by PFN)
      // Output (best-effort):
      //   entry->gpa      = hooked PFN (gpa >> 12)
      //   entry->aux      = hook read PFN
      //   entry->reserved = hook exec PFN
      //   entry->cr3      = dummy PFN (for comparison)
      auto const gpa = entry->gpa;
      if (!gpa) {
        entry->status = static_cast<uint32_t>(shared_queue_entry_status::err_translate);
        goto done_entry;
      }

      auto const pfn = (gpa >> 12);
      auto const hook = find_ept_hook(cpu->ept, pfn);
      if (!hook) {
        // Not hooked: return zeros but mark done so the caller can distinguish "not hooked"
        // from translation errors.
        entry->gpa      = pfn;
        entry->aux      = 0;
        entry->reserved = 0;
        entry->cr3      = cpu->ept.dummy_page_pfn;
        entry->status   = static_cast<uint32_t>(shared_queue_entry_status::done);
        goto done_entry;
      }

      entry->gpa      = pfn;
      entry->aux      = hook->read_pfn;
      entry->reserved = hook->exec_pfn;
      entry->cr3      = cpu->ept.dummy_page_pfn;
      entry->status   = static_cast<uint32_t>(shared_queue_entry_status::done);
    } break;

    case shared_queue_cmd::devirt_all: {
      // Request global devirtualization (no VMCALL path). The current CPU will also
      // re-check stop_requested after queue processing and exit on the same VM-exit.
      request_global_devirtualize();
      entry->status = static_cast<uint32_t>(shared_queue_entry_status::done);
    } break;

    case shared_queue_cmd::tsc_diag_dump: {
      // Copy recent TSC diag snapshots into a user-provided buffer:
      //   entry->gva  : dst buffer VA (current process)
      //   entry->size : dst buffer size (recommended <= 0x1000)
      auto const user_gva = reinterpret_cast<void*>(entry->gva);
      auto size = entry->size;
      if (size > 0x1000u)
        size = 0x1000u;

      size_t dst_remaining = 0;
      auto* const dst = gva2hva(guest_cr3, user_gva, &dst_remaining);
      if (!dst || dst_remaining < size) {
        entry->status = static_cast<uint32_t>(shared_queue_entry_status::err_translate);
        goto done_entry;
      }

      uint8_t tmp[0x1000] = {};
      uint64_t newest = 0;
      auto const count = tsc_diag_dump(tmp, size, &newest);

      host_exception_info e;
      memcpy_safe(e, dst, tmp, size);
      if (e.exception_occurred) {
        entry->status = static_cast<uint32_t>(shared_queue_entry_status::err_translate);
        goto done_entry;
      }

      entry->aux      = count;
      entry->reserved = newest;
      entry->size     = size;
      entry->status   = static_cast<uint32_t>(shared_queue_entry_status::done);
    } break;

    case shared_queue_cmd::exit_stats_dump: {
      // Copy aggregated exit stats into a user-provided buffer:
      //   entry->gva  : dst buffer VA (current process)
      //   entry->size : dst buffer size (must be >= sizeof(exit_stats_dump), capped at 0x1000)
      auto const user_gva = reinterpret_cast<void*>(entry->gva);
      auto size = entry->size;
      if (size > 0x1000u)
        size = 0x1000u;

      if (size < sizeof(exit_stats_dump)) {
        entry->status = static_cast<uint32_t>(shared_queue_entry_status::err_translate);
        goto done_entry;
      }

      size_t dst_remaining = 0;
      auto* const dst = gva2hva(guest_cr3, user_gva, &dst_remaining);
      if (!dst || dst_remaining < size) {
        entry->status = static_cast<uint32_t>(shared_queue_entry_status::err_translate);
        goto done_entry;
      }

      uint8_t tmp[0x1000] = {};
      auto* const out = reinterpret_cast<exit_stats_dump*>(tmp);
      exit_stats_build(*out);

      host_exception_info e;
      memcpy_safe(e, dst, tmp, size);
      if (e.exception_occurred) {
        entry->status = static_cast<uint32_t>(shared_queue_entry_status::err_translate);
        goto done_entry;
      }

      entry->aux    = sizeof(exit_stats_dump);
      entry->size   = size;
      entry->status = static_cast<uint32_t>(shared_queue_entry_status::done);
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


