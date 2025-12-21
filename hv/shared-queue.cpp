#include "shared-queue.h"

#include "logger.h"
#include "vcpu.h"
#include "vmx.h"

namespace hv {

namespace {

spin_lock g_queue_lock = {};
shared_queue_context g_queue_entries[shared_queue_max_entries] = {};

} // namespace

shared_queue_register_result register_shared_queue(
  cr3 const guest_cr3, shared_queue_register_request const& req) {
  shared_queue_register_result result{};

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

void process_shared_queue(vcpu* const /*cpu*/) {
  cr3 guest_cr3;
  guest_cr3.flags = vmx_vmread(VMCS_GUEST_CR3);

  auto const ctx = find_shared_queue(guest_cr3);
  if (!ctx)
    return;

  size_t header_remaining = 0;
  auto* header = reinterpret_cast<shared_queue_header*>(
    gva2hva(guest_cr3, reinterpret_cast<void*>(ctx->queue_gva), &header_remaining));

  if (!header || header_remaining < sizeof(shared_queue_header)) {
    HV_LOG_ERROR("[sq] header translation failed: gva=%p cr3=%p", ctx->queue_gva, guest_cr3.flags);
    invalidate_shared_queue(guest_cr3);
    return;
  }

  auto const capacity = (ctx->queue_size > sizeof(shared_queue_header))
    ? static_cast<uint32_t>((ctx->queue_size - sizeof(shared_queue_header)) / sizeof(shared_queue_entry))
    : 0;

  if (capacity == 0)
    return;

  auto head = header->head;
  auto tail = header->tail;

  uint32_t processed = 0;
  constexpr uint32_t max_batch = 4;

  while (tail != head && processed < max_batch) {
    auto const idx = tail % capacity;
    auto const entry_gva = ctx->queue_gva + sizeof(shared_queue_header)
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
    default:
      entry->status = static_cast<uint32_t>(shared_queue_entry_status::err_unimplemented);
      break;
    }

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
}

} // namespace hv


