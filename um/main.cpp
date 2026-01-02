#include <algorithm>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <numeric>
#include <string>
#include <vector>
#include <intrin.h>

#include "hv.h"
#include "dumper.h"

static void usage(char const* const exe) {
  printf("usage:\n");
  printf("  %s --menu         # interactive menu (recommended)\n", exe);
  printf("  %s --devirt-all    # run hypercall_unload on every CPU (useful before unloading hv.sys when EPT self-hide is enabled)\n", exe);
  printf("  %s --demo          # run the shared-queue demo (legacy behavior)\n", exe);
  printf("  %s --bench-tsc     # benchmark hypercall latency using RDTSC/RDTSCP\n", exe);
  printf("  %s --diag-tsc      # dump recent TSC compensation diagnostics via shared-queue (no hypercall)\n", exe);
  printf("  %s --help\n", exe);
}

static void wait_enter() {
  printf("Press Enter to continue...\n");
  fflush(stdout);
  std::string _;
  std::getline(std::cin, _);
}

static bool ensure_hv_running() {
  if (!hv::is_hv_running()) {
    printf("[um][err] HV not running.\n");
    return false;
  }
  return true;
}

static void action_ping() {
  if (!ensure_hv_running())
    return;
  auto const sig = hv::ping();
  printf("[um] ping => 0x%llX\n", sig);
}

static void action_test() {
  if (!ensure_hv_running())
    return;
  auto const r = hv::test(1, 2, 3, 4, 5, 6);
  printf("[um] test => 0x%llX\n", r);
}

struct bench_stats {
  uint64_t min;
  uint64_t max;
  double   avg;
  uint64_t p50;
  uint64_t p90;
  uint64_t p99;
};

static bench_stats compute_stats(std::vector<uint64_t> const& samples) {
  bench_stats s{};
  if (samples.empty())
    return s;

  auto sorted = samples;
  std::sort(sorted.begin(), sorted.end());

  auto pct = [&](double p) -> uint64_t {
    auto const idx = static_cast<size_t>(p * (sorted.size() - 1));
    return sorted[idx];
  };

  long double sum = 0.0L;
  for (auto v : samples)
    sum += static_cast<long double>(v);

  s.min = sorted.front();
  s.max = sorted.back();
  s.avg = static_cast<double>(sum) / static_cast<double>(samples.size());
  s.p50 = pct(0.50);
  s.p90 = pct(0.90);
  s.p99 = pct(0.99);
  return s;
}

static uint64_t rdtscp_now() {
  unsigned int aux = 0;
  _mm_lfence();
  auto const t = __rdtscp(&aux);
  _mm_lfence();
  return t;
}

static void action_bench_tsc() {
  if (!ensure_hv_running())
    return;

  constexpr int warmup = 200;
  constexpr int iters  = 5000;

  // Pin to CPU0 to reduce jitter (scheduler migration hurts timing).
  auto const thread = GetCurrentThread();
  auto const prev_affinity = SetThreadAffinityMask(thread, 1ull);

  hv::queue_handshake_request req{};
  req.queue = nullptr;
  req.size  = 0;
  req.magic = 0x1122334455667788ull;
  req.seed  = 0x8877665544332211ull;

  // Warm-up to stabilize caches/TLBs.
  for (int i = 0; i < warmup; ++i) {
    (void)hv::queue_handshake(req);
  }

  std::vector<uint64_t> samples;
  samples.reserve(iters);

  for (int i = 0; i < iters; ++i) {
    auto const t0 = rdtscp_now();
    (void)hv::queue_handshake(req);
    auto const t1 = rdtscp_now();
    samples.push_back(t1 - t0);
  }

  if (prev_affinity)
    SetThreadAffinityMask(thread, prev_affinity);

  auto const stats = compute_stats(samples);
  printf("[um][bench] cpuid-handshake latency (cycles):\n");
  printf("  n=%zu min=%llu max=%llu avg=%.2f p50=%llu p90=%llu p99=%llu\n",
    samples.size(),
    static_cast<unsigned long long>(stats.min),
    static_cast<unsigned long long>(stats.max),
    stats.avg,
    static_cast<unsigned long long>(stats.p50),
    static_cast<unsigned long long>(stats.p90),
    static_cast<unsigned long long>(stats.p99));
}

static void action_diag_tsc() {
  if (!ensure_hv_running())
    return;

  // Register a shared queue (2 pages) so we can issue shared-queue commands.
  constexpr size_t queue_size = 0x2000;
  uint8_t* queue = static_cast<uint8_t*>(
    VirtualAlloc(nullptr, queue_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

  if (!queue) {
    printf("[um][err] VirtualAlloc failed (gle=0x%08X).\n", GetLastError());
    return;
  }

  if (!VirtualLock(queue, queue_size)) {
    printf("[um][err] VirtualLock failed (gle=0x%08X).\n", GetLastError());
    VirtualFree(queue, 0, MEM_RELEASE);
    return;
  }

  memset(queue, 0, queue_size);

  hv::queue_handshake_request req{};
  req.queue = queue;
  req.size  = static_cast<uint32_t>(queue_size);
  req.magic = 0xD1A6D1A6D1A6D1A6ull;
  req.seed  = 0xF00DF00DF00DF00Dull;

  auto const hs = hv::queue_handshake(req);
  if (hs.signature != hv::hypervisor_signature ||
      hs.status != hv::queue_register_status::success) {
    printf("[um][err] queue handshake failed: signature=0x%llX status=%u pages=%u\n",
      hs.signature, static_cast<uint32_t>(hs.status), hs.page_count);
    VirtualUnlock(queue, queue_size);
    VirtualFree(queue, 0, MEM_RELEASE);
    return;
  }

  // Output buffer: one page (HV side enforces <= 0x1000 for now).
  constexpr uint32_t out_size = 0x1000;
  auto* out = static_cast<uint8_t*>(
    VirtualAlloc(nullptr, out_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
  if (!out) {
    printf("[um][err] VirtualAlloc(out) failed (gle=0x%08X).\n", GetLastError());
    VirtualUnlock(queue, queue_size);
    VirtualFree(queue, 0, MEM_RELEASE);
    return;
  }
  memset(out, 0, out_size);

  auto* qhdr = hv::sq_header(queue);
  auto* qent = hv::sq_entries(queue);
  qhdr->head = 0;
  qhdr->tail = 0;

  ZeroMemory(&qent[0], sizeof(hv::shared_queue_entry));
  qent[0].cmd    = static_cast<uint32_t>(hv::shared_queue_cmd::tsc_diag_dump);
  qent[0].status = static_cast<uint32_t>(hv::shared_queue_entry_status::pending);
  qent[0].gva    = reinterpret_cast<uint64_t>(out);
  qent[0].size   = out_size;

  _mm_mfence();
  qhdr->head = 1;
  _mm_mfence();

  // Kick HV: any VM-exit will process the queue batch.
  int regs[4] = {};
  __cpuid(regs, 0);

  // Wait for completion (best-effort; kick periodically).
  for (int i = 0; i < 2000; ++i) {
    if (qent[0].status != static_cast<uint32_t>(hv::shared_queue_entry_status::pending))
      break;
    if ((i % 50) == 0)
      __cpuid(regs, 0);
    Sleep(0);
  }

  if (qent[0].status != static_cast<uint32_t>(hv::shared_queue_entry_status::done)) {
    printf("[um][err] diag dump not completed (status=0x%08X).\n", qent[0].status);
  } else {
    auto const* hdr = reinterpret_cast<hv::tsc_diag_dump_header const*>(out);
    printf("[um][diag] tsc_diag_dump: newest_seq=%llu count=%u entry_size=%u (aux=%llu newest=%llu)\n",
      static_cast<unsigned long long>(hdr->newest_seq),
      hdr->count,
      hdr->entry_size,
      static_cast<unsigned long long>(qent[0].aux),
      static_cast<unsigned long long>(qent[0].reserved));

    if (hdr->count == 0) {
      // Keep this message ASCII-only to avoid mojibake on non-UTF8 consoles.
      printf("[um][diag] no snapshots (HV_TSC_DIAG disabled or sampling condition not hit).\n");
    } else if (hdr->entry_size != sizeof(hv::tsc_diag_snapshot)) {
      printf("[um][diag] entry_size mismatch: got=%u expected=%zu\n",
        hdr->entry_size, sizeof(hv::tsc_diag_snapshot));
    } else {
      auto const* snaps = reinterpret_cast<hv::tsc_diag_snapshot const*>(
        out + sizeof(hv::tsc_diag_dump_header));
      auto const show = (hdr->count > 16) ? 16u : hdr->count;
      for (uint32_t i = 0; i < show; ++i) {
        auto const& s = snaps[i];
        printf("  [%2u] seq=%llu cpu=%u reason=%u hide=%u elapsed=%llu off:%lld->%lld last=%llu rip=%llX eax=%X sig=%llX\n",
          i,
          static_cast<unsigned long long>(s.seq),
          s.cpu,
          s.exit_reason,
          s.hide_in,
          static_cast<unsigned long long>(s.elapsed),
          static_cast<long long>(s.tsc_offset_before),
          static_cast<long long>(s.tsc_offset_after),
          static_cast<unsigned long long>(s.last_guest_tsc),
          static_cast<unsigned long long>(s.guest_rip),
          static_cast<unsigned int>(s.cpuid_eax),
          static_cast<unsigned long long>(s.signature_rax));
      }
    }
  }

  VirtualFree(out, 0, MEM_RELEASE);

  // Best-effort deregister (avoid CR3/page reuse issues).
  hv::queue_handshake_request dereg{};
  dereg.queue = nullptr;
  dereg.size  = 0;
  dereg.magic = req.magic;
  dereg.seed  = req.seed;
  __try {
    (void)hv::queue_handshake(dereg);
  } __except (EXCEPTION_EXECUTE_HANDLER) {}

  VirtualUnlock(queue, queue_size);
  VirtualFree(queue, 0, MEM_RELEASE);
}

static void action_diag_exits() {
  if (!ensure_hv_running())
    return;

  // Register a shared queue (2 pages) so we can issue shared-queue commands.
  constexpr size_t queue_size = 0x2000;
  uint8_t* queue = static_cast<uint8_t*>(
    VirtualAlloc(nullptr, queue_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

  if (!queue) {
    printf("[um][err] VirtualAlloc failed (gle=0x%08X).\n", GetLastError());
    return;
  }

  if (!VirtualLock(queue, queue_size)) {
    printf("[um][err] VirtualLock failed (gle=0x%08X).\n", GetLastError());
    VirtualFree(queue, 0, MEM_RELEASE);
    return;
  }

  memset(queue, 0, queue_size);

  hv::queue_handshake_request req{};
  req.queue = queue;
  req.size  = static_cast<uint32_t>(queue_size);
  req.magic = 0xE17157A7E17157A7ull;
  req.seed  = 0x5151515151515151ull;

  auto const hs = hv::queue_handshake(req);
  if (hs.signature != hv::hypervisor_signature ||
      hs.status != hv::queue_register_status::success) {
    printf("[um][err] queue handshake failed: signature=0x%llX status=%u pages=%u\n",
      hs.signature, static_cast<uint32_t>(hs.status), hs.page_count);
    VirtualUnlock(queue, queue_size);
    VirtualFree(queue, 0, MEM_RELEASE);
    return;
  }

  // Output buffer (one page).
  constexpr uint32_t out_size = 0x1000;
  auto* out = static_cast<uint8_t*>(
    VirtualAlloc(nullptr, out_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
  if (!out) {
    printf("[um][err] VirtualAlloc(out) failed (gle=0x%08X).\n", GetLastError());
    VirtualUnlock(queue, queue_size);
    VirtualFree(queue, 0, MEM_RELEASE);
    return;
  }
  memset(out, 0, out_size);

  auto* qhdr = hv::sq_header(queue);
  auto* qent = hv::sq_entries(queue);
  qhdr->head = 0;
  qhdr->tail = 0;

  auto do_dump = [&](hv::exit_stats_dump& dst) -> bool {
    memset(out, 0, out_size);
    qhdr->head = 0;
    qhdr->tail = 0;

    ZeroMemory(&qent[0], sizeof(hv::shared_queue_entry));
    qent[0].cmd    = static_cast<uint32_t>(hv::shared_queue_cmd::exit_stats_dump);
    qent[0].status = static_cast<uint32_t>(hv::shared_queue_entry_status::pending);
    qent[0].gva    = reinterpret_cast<uint64_t>(out);
    qent[0].size   = out_size;

    _mm_mfence();
    qhdr->head = 1;
    _mm_mfence();

    // Kick HV: any VM-exit will process the queue batch.
    int regs[4] = {};
    __cpuid(regs, 0);

    // Wait for completion (best-effort; kick periodically).
    for (int i = 0; i < 2000; ++i) {
      if (qent[0].status != static_cast<uint32_t>(hv::shared_queue_entry_status::pending))
        break;
      if ((i % 50) == 0)
        __cpuid(regs, 0);
      Sleep(0);
    }

    if (qent[0].status != static_cast<uint32_t>(hv::shared_queue_entry_status::done)) {
      printf("[um][err] exit stats dump not completed (status=0x%08X).\n", qent[0].status);
      return false;
    }

    dst = *reinterpret_cast<hv::exit_stats_dump const*>(out);
    return true;
  };

  hv::exit_stats_dump a{}, b{};
  if (!do_dump(a)) {
    VirtualFree(out, 0, MEM_RELEASE);
    VirtualUnlock(queue, queue_size);
    VirtualFree(queue, 0, MEM_RELEASE);
    return;
  }

  // Sample delta over ~1 second to identify ongoing VM-exit sources.
  Sleep(1000);

  if (!do_dump(b)) {
    VirtualFree(out, 0, MEM_RELEASE);
    VirtualUnlock(queue, queue_size);
    VirtualFree(queue, 0, MEM_RELEASE);
    return;
  }

  auto diff_u64 = [](uint64_t x, uint64_t y) -> uint64_t { return (y >= x) ? (y - x) : 0ull; };

  printf("[um][exit] total=%llu -> %llu (delta/s ~%llu)\n",
    static_cast<unsigned long long>(a.exit_total),
    static_cast<unsigned long long>(b.exit_total),
    static_cast<unsigned long long>(diff_u64(a.exit_total, b.exit_total)));
  printf("  tsc_offset_range: [%lld .. %lld] -> [%lld .. %lld]\n",
    static_cast<long long>(a.tsc_offset_min),
    static_cast<long long>(a.tsc_offset_max),
    static_cast<long long>(b.tsc_offset_min),
    static_cast<long long>(b.tsc_offset_max));
  printf("  cpuid=%llu rdmsr=%llu wrmsr=%llu exc_nmi=%llu nmi_win=%llu preempt=%llu\n",
    static_cast<unsigned long long>(diff_u64(a.exit_cpuid, b.exit_cpuid)),
    static_cast<unsigned long long>(diff_u64(a.exit_rdmsr, b.exit_rdmsr)),
    static_cast<unsigned long long>(diff_u64(a.exit_wrmsr, b.exit_wrmsr)),
    static_cast<unsigned long long>(diff_u64(a.exit_exception_or_nmi, b.exit_exception_or_nmi)),
    static_cast<unsigned long long>(diff_u64(a.exit_nmi_window, b.exit_nmi_window)),
    static_cast<unsigned long long>(diff_u64(a.exit_preemption_timer, b.exit_preemption_timer)));
  printf("  ept=%llu movcr=%llu mtf=%llu rdtsc=%llu rdtscp=%llu\n",
    static_cast<unsigned long long>(diff_u64(a.exit_ept_violation, b.exit_ept_violation)),
    static_cast<unsigned long long>(diff_u64(a.exit_mov_cr, b.exit_mov_cr)),
    static_cast<unsigned long long>(diff_u64(a.exit_monitor_trap_flag, b.exit_monitor_trap_flag)),
    static_cast<unsigned long long>(diff_u64(a.exit_rdtsc, b.exit_rdtsc)),
    static_cast<unsigned long long>(diff_u64(a.exit_rdtscp, b.exit_rdtscp)));

  // Still show absolute top lists (they are cumulative, but useful to spot offenders).
  printf("  top RDMSR (cumulative):\n");
  for (uint32_t i = 0; i < hv::exit_stats_top_n; ++i) {
    auto const& e = b.top_rdmsr[i];
    if (e.count == 0)
      break;
    printf("    msr=0x%08X count=%llu\n", e.msr, static_cast<unsigned long long>(e.count));
  }

  printf("  top WRMSR (cumulative):\n");
  for (uint32_t i = 0; i < hv::exit_stats_top_n; ++i) {
    auto const& e = b.top_wrmsr[i];
    if (e.count == 0)
      break;
    printf("    msr=0x%08X count=%llu\n", e.msr, static_cast<unsigned long long>(e.count));
  }

  VirtualFree(out, 0, MEM_RELEASE);

  // Best-effort deregister.
  hv::queue_handshake_request dereg{};
  dereg.queue = nullptr;
  dereg.size  = 0;
  dereg.magic = req.magic;
  dereg.seed  = req.seed;
  __try {
    (void)hv::queue_handshake(dereg);
  } __except (EXCEPTION_EXECUTE_HANDLER) {}

  VirtualUnlock(queue, queue_size);
  VirtualFree(queue, 0, MEM_RELEASE);
}

static void action_devirt_all() {
  if (!ensure_hv_running())
    return;

  printf("[um] Requesting global devirtualization via shared queue...\n");
  fflush(stdout);

  // Allocate a small shared queue (2 pages) and register it via CPUID handshake.
  constexpr size_t queue_size = 0x2000;
  uint8_t* queue = static_cast<uint8_t*>(
    VirtualAlloc(nullptr, queue_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

  if (!queue) {
    printf("[um][err] VirtualAlloc failed (gle=0x%08X).\n", GetLastError());
    return;
  }

  if (!VirtualLock(queue, queue_size)) {
    printf("[um][err] VirtualLock failed (gle=0x%08X).\n", GetLastError());
    VirtualFree(queue, 0, MEM_RELEASE);
    return;
  }

  memset(queue, 0, queue_size);

  hv::queue_handshake_request req{};
  req.queue = queue;
  req.size  = static_cast<uint32_t>(queue_size);
  req.magic = 0xC0FFEE123456789ull;
  req.seed  = 0xBADF00DCAFEBABEull;

  auto const hs = hv::queue_handshake(req);
  printf("[um] queue handshake: signature=0x%llX status=%u pages=%u magic_echo=0x%llX\n",
    hs.signature, static_cast<uint32_t>(hs.status), hs.page_count, hs.echoed_magic);

  if (hs.signature != hv::hypervisor_signature ||
      hs.status != hv::queue_register_status::success) {
    printf("[um][err] handshake failed.\n");
    VirtualUnlock(queue, queue_size);
    VirtualFree(queue, 0, MEM_RELEASE);
    return;
  }

  // Enqueue a single "devirt_all" command.
  auto* qhdr = hv::sq_header(queue);
  auto* qent = hv::sq_entries(queue);
  qhdr->head = 0;
  qhdr->tail = 0;

  ZeroMemory(&qent[0], sizeof(hv::shared_queue_entry));
  qent[0].cmd    = static_cast<uint32_t>(hv::shared_queue_cmd::devirt_all);
  qent[0].status = static_cast<uint32_t>(hv::shared_queue_entry_status::pending);

  _mm_mfence();
  qhdr->head = 1;
  _mm_mfence();

  // Kick all CPUs to force immediate VM-exits and complete devirtualization deterministically.
  // Rationale:
  // - devirt_all sets a global stop flag in the HV (root-mode).
  // - each logical processor devirtualizes on its NEXT VM-exit.
  // - on multi-core (and especially in idle), waiting for timers can race with driver unload.
  printf("[um] Forcing a VM-exit on each CPU (CPUID) to complete devirtualization...\n");
  fflush(stdout);

  // Kick current CPU first to ensure the queue is processed and stop is requested.
  {
    auto const ks = hv::queue_handshake(req);
    printf("[um] kick result: signature=0x%llX status=%u pages=%u magic_echo=0x%llX\n",
      ks.signature, static_cast<uint32_t>(ks.status), ks.page_count, ks.echoed_magic);
    fflush(stdout);
  }

  // Then force at least one VM-exit on every CPU.
  hv::for_each_cpu([&](uint32_t cpu_idx) {
    int regs[4] = {};
    __cpuid(regs, 0);
    printf("[um] cpu%u cpuid-kick done.\n", cpu_idx);
    fflush(stdout);
  });

  // Verify devirtualization: once a CPU VMXOFF'd, the CPUID handshake won't be intercepted
  // and hv::is_hv_running() (pinned to that CPU) should return false.
  SYSTEM_INFO info{};
  GetSystemInfo(&info);
  constexpr DWORD timeout_ms = 5000;
  DWORD waited = 0;
  while (waited < timeout_ms) {
    uint32_t done = 0;
    hv::for_each_cpu([&](uint32_t /*cpu_idx*/) {
      if (!hv::is_hv_running())
        ++done;
    });
    if (done >= info.dwNumberOfProcessors) {
      printf("[um] Devirtualization complete on all CPUs (%u/%u).\n",
        done, info.dwNumberOfProcessors);
      fflush(stdout);
      break;
    }

    Sleep(50);
    waited += 50;
  }

  printf("[um] Requested. Now stop/unload hv.sys via SCM. Keep this program running until done.\n");
  wait_enter();

  VirtualUnlock(queue, queue_size);
  VirtualFree(queue, 0, MEM_RELEASE);
}

static int action_shared_queue_demo() {
  if (!ensure_hv_running()) {
    wait_enter();
    return 0;
  }

  // 1) Allocate & lock a shared queue buffer (example: 8KB).
  constexpr size_t queue_size = 0x2000;
  printf("[um] allocating queue size=0x%zx bytes.\n", queue_size);
  uint8_t* queue = static_cast<uint8_t*>(
    VirtualAlloc(nullptr, queue_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

  if (!queue) {
    printf("[um][err] failed to allocate shared queue (gle=0x%08X).\n", GetLastError());
    printf("Press Enter to exit.\n");
    getchar();
    return 0;
  }

  if (!VirtualLock(queue, queue_size)) {
    printf("[um][err] VirtualLock failed (gle=0x%08X).\n", GetLastError());
    VirtualFree(queue, 0, MEM_RELEASE);
    printf("Press Enter to exit.\n");
    getchar();
    return 0;
  }

  // Touch pages to avoid lazy allocation.
  memset(queue, 0xA5, queue_size);

  // 2) Register via CPUID handshake.
  printf("[um] queue ptr=%p\n", queue);
  fflush(stdout);
  hv::queue_handshake_request req{};
  req.queue = queue;
  req.size  = static_cast<uint32_t>(queue_size);
  req.magic = 0xC0FFEE123456789ull;
  req.seed  = 0xBADF00DCAFEBABEull;

  printf("[um] sending handshake... magic=%llX seed=%llX\n", req.magic, req.seed);
  fflush(stdout);
  hv::queue_handshake_result hs{};
  __try {
    hs = hv::queue_handshake(req);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    printf("[um][err] handshake threw exception: 0x%08X\n", GetExceptionCode());
    VirtualUnlock(queue, queue_size);
    VirtualFree(queue, 0, MEM_RELEASE);
    printf("Press Enter to exit.\n");
    getchar();
    return 0;
  }

  printf("[um] queue handshake: signature=%llX status=%u pages=%u magic_echo=%llX\n",
    hs.signature, static_cast<uint32_t>(hs.status), hs.page_count, hs.echoed_magic);
  fflush(stdout);

  if (hs.signature != hv::hypervisor_signature ||
      hs.status != hv::queue_register_status::success) {
    printf("[um][err] handshake failed, abort.\n");
    VirtualUnlock(queue, queue_size);
    VirtualFree(queue, 0, MEM_RELEASE);
    printf("Press Enter to exit.\n");
    getchar();
    return 0;
  }

  // TODO: Hook more producer logic here (fill descriptors, advance head, etc).

  printf("[um] handshake OK, continuing to hide HV pages...\n");
  fflush(stdout);

  // 3) Publish a NOP entry to validate queue consumption.
  auto* qhdr = hv::sq_header(queue);
  auto* qent = hv::sq_entries(queue);
  qhdr->head = 0;
  qhdr->tail = 0;

  // Reserve a scratch area inside the queue (page #2) for read/write buffers.
  uint8_t* scratch = reinterpret_cast<uint8_t*>(reinterpret_cast<uint8_t*>(queue) + 0x1000);
  ZeroMemory(scratch, 0x200);

  // Clear the first entry to avoid 0xA5 pattern affecting logs.
  ZeroMemory(&qent[0], sizeof(hv::shared_queue_entry));
  qent[0].cmd    = static_cast<uint32_t>(hv::shared_queue_cmd::nop);
  qent[0].status = static_cast<uint32_t>(hv::shared_queue_entry_status::pending);
  qent[0].size   = 0;
  qent[0].flags  = 0;
  qent[0].aux    = 0;

  // Publish head=1
  _mm_mfence();
  qhdr->head = 1;
  _mm_mfence();

  // 4) Prepare virt test buffers
  auto* virt_src = scratch + 0x100; // 0x80 bytes
  auto* virt_dst = scratch + 0x180; // 0x80 bytes
  for (size_t i = 0; i < 0x80; ++i)
    virt_src[i] = static_cast<uint8_t>(i);
  ZeroMemory(virt_dst, 0x80);

  // write_virt: src=virt_src (current), dst=virt_dst (same cr3)
  ZeroMemory(&qent[1], sizeof(hv::shared_queue_entry));
  qent[1].cmd    = static_cast<uint32_t>(hv::shared_queue_cmd::write_virt);
  qent[1].status = static_cast<uint32_t>(hv::shared_queue_entry_status::pending);
  qent[1].cr3    = 0; // 0 = current CR3
  qent[1].gva    = reinterpret_cast<uint64_t>(virt_dst); // dst VA
  qent[1].gpa    = reinterpret_cast<uint64_t>(virt_src); // src VA
  qent[1].size   = 0x80;

  // read_virt: src=virt_dst (target), dst=virt_dst2 (current)
  auto* virt_dst2 = scratch + 0x200; // 0x80 bytes
  ZeroMemory(virt_dst2, 0x80);

  ZeroMemory(&qent[2], sizeof(hv::shared_queue_entry));
  qent[2].cmd    = static_cast<uint32_t>(hv::shared_queue_cmd::read_virt);
  qent[2].status = static_cast<uint32_t>(hv::shared_queue_entry_status::pending);
  qent[2].cr3    = 0; // current CR3
  qent[2].gva    = reinterpret_cast<uint64_t>(virt_dst);  // src VA
  qent[2].gpa    = reinterpret_cast<uint64_t>(virt_dst2); // dst VA
  qent[2].size   = 0x80;

  _mm_mfence();
  qhdr->head = 3; // publish 3 entries (nop + write_virt + read_virt)
  _mm_mfence();

  // In some environments (nested/VMware), the VMX preemption timer may be unstable,
  // causing no new VM-exits to poll the shared queue. Do a "kick" by repeating the
  // CPUID handshake to force a VM-exit and process the queue promptly.
  {
    printf("[um] kicking HV to process queue...\n");
    fflush(stdout);
    __try {
      auto const ks = hv::queue_handshake(req);
      printf("[um] kick result: signature=%llX status=%u pages=%u magic_echo=%llX\n",
        ks.signature, static_cast<uint32_t>(ks.status), ks.page_count, ks.echoed_magic);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      printf("[um][warn] kick threw exception: 0x%08X\n", GetExceptionCode());
    }
    fflush(stdout);
  }

  // Poll tail to verify consumption.
  while (!GetAsyncKeyState(VK_RETURN)) {
    static bool entry0_reported = false;
    static bool entry1_reported = false;
    static bool entry2_reported = false;
    auto const tail = qhdr->tail;
    if (!entry0_reported &&
        tail > 0 &&
        qent[0].status == static_cast<uint32_t>(hv::shared_queue_entry_status::done)) {
      printf("[um] queue entry 0 done, tail=%u\n", tail);
      entry0_reported = true;
    }
    if (!entry1_reported &&
        tail > 1 &&
        qent[1].status == static_cast<uint32_t>(hv::shared_queue_entry_status::done)) {
      printf("[um] queue entry 1 done (write_virt) tail=%u size=%u\n", tail, qent[1].size);
      entry1_reported = true;
    }
    if (!entry2_reported &&
        tail > 2 &&
        qent[2].status == static_cast<uint32_t>(hv::shared_queue_entry_status::done)) {
      printf("[um] queue entry 2 done (read_virt) tail=%u size=%u\n", tail, qent[2].size);
      printf("[um] read_virt buffer (first 32 bytes):\n  ");
      for (size_t i = 0; i < 32; ++i) {
        printf("%02X ", virt_dst2[i]);
      }
      printf("\n");
      entry2_reported = true;
    }

    if (entry0_reported && entry1_reported && entry2_reported)
      break;

    Sleep(200);
  }

  // 5) Validate whether EPT self-hide is effective:
  // NOTE: shared-queue read_virt reads physical memory in root-mode and does NOT go through EPT,
  // so you may still see "MZ" even if hide is effective. We query EPT mapping instead.
  void* hv_base = nullptr;
  uint32_t hv_size = 0;
  if (find_loaded_driver("hv.sys", hv_base, hv_size)) {
    printf("[um] hv.sys base=%p size=0x%X\n", hv_base, hv_size);

    ZeroMemory(&qent[3], sizeof(hv::shared_queue_entry));
    qent[3].cmd    = static_cast<uint32_t>(hv::shared_queue_cmd::query_ept_map);
    qent[3].status = static_cast<uint32_t>(hv::shared_queue_entry_status::pending);
    qent[3].cr3    = 0; // current guest CR3
    qent[3].gva    = reinterpret_cast<uint64_t>(hv_base); // kernel VA

    _mm_mfence();
    qhdr->head = 4;
    _mm_mfence();

    // wait for entry 3
    for (int i = 0; i < 50; ++i) { // ~10s
      if (qhdr->tail > 3 &&
          qent[3].status == static_cast<uint32_t>(hv::shared_queue_entry_status::done)) {
        auto const orig_pfn  = qent[3].gpa;
        auto const mapped_pfn = qent[3].aux;
        auto const dummy_pfn  = qent[3].reserved;
        printf("[um] EPT map for hv.sys base: orig_pfn=0x%llX mapped_pfn=0x%llX dummy_pfn=0x%llX\n",
          orig_pfn, mapped_pfn, dummy_pfn);
        if (dummy_pfn != 0 && mapped_pfn == dummy_pfn)
          printf("[um][ok] EPT self-hide effective (mapped to dummy).\n");
        else
          printf("[um][warn] EPT self-hide NOT effective for this VA (not mapped to dummy).\n");
        break;
      }
      Sleep(200);
    }
  } else {
    printf("[um][warn] failed to locate hv.sys in loaded module list; skip self-hide check.\n");
  }

  // 6) Deregister the shared queue before exit to avoid CR3/page reuse issues.
  hv::queue_handshake_request dereg{};
  dereg.queue = nullptr;
  dereg.size  = 0;
  dereg.magic = req.magic;
  dereg.seed  = req.seed;
  __try {
    auto const dr = hv::queue_handshake(dereg);
    printf("[um] queue deregister: signature=%llX status=%u pages=%u magic_echo=%llX\n",
      dr.signature, static_cast<uint32_t>(dr.status), dr.page_count, dr.echoed_magic);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    printf("[um][warn] deregister threw exception: 0x%08X\n", GetExceptionCode());
  }

  printf("[um] exiting.\n");
  fflush(stdout);
  wait_enter();
  return 0;
}

static void run_menu() {
  for (;;) {
    printf("\n========== hv um menu ==========\n");
    printf("1) ping (check if HV is running)\n");
    printf("2) test (example hypercall)\n");
    printf("3) shared-queue demo\n");
    printf("4) devirt-all (run hypercall_unload on each CPU; use before unloading hv.sys when self-hide is enabled)\n");
    printf("5) bench-tsc (measure hypercall latency via RDTSC/RDTSCP)\n");
    printf("6) diag-tsc (dump TSC compensation diagnostics via shared-queue)\n");
    printf("7) diag-exits (dump VM-exit/MSR statistics via shared-queue)\n");
    printf("0) exit\n");
    printf("Select: ");
    fflush(stdout);

    std::string line;
    if (!std::getline(std::cin, line))
      return;
    if (line.empty())
      continue;

    int choice = -1;
    try {
      choice = std::stoi(line);
    } catch (...) {
      printf("[um][err] invalid input: %s\n", line.c_str());
      continue;
    }

    switch (choice) {
    case 1:
      action_ping();
      wait_enter();
      break;
    case 2:
      action_test();
      wait_enter();
      break;
    case 3:
      action_shared_queue_demo();
      break;
    case 4:
      action_devirt_all();
      wait_enter();
      break;
    case 5:
      action_bench_tsc();
      wait_enter();
      break;
    case 6:
      action_diag_tsc();
      wait_enter();
      break;
    case 7:
      action_diag_exits();
      wait_enter();
      break;
    case 0:
      return;
    default:
      printf("[um][err] unknown option: %d\n", choice);
      break;
    }
  }
}

int main(int argc, char** argv) {
  if (argc >= 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
    usage(argv[0]);
    return 0;
  }

  if (argc >= 2 && strcmp(argv[1], "--devirt-all") == 0) {
    action_devirt_all();
    return 0;
  }

  if (argc >= 2 && strcmp(argv[1], "--bench-tsc") == 0) {
    action_bench_tsc();
    return 0;
  }

  if (argc >= 2 && strcmp(argv[1], "--diag-tsc") == 0) {
    action_diag_tsc();
    return 0;
  }

  if (argc >= 2 && strcmp(argv[1], "--demo") == 0) {
    return action_shared_queue_demo();
  }

  // Default: interactive menu.
  if (argc >= 2 && strcmp(argv[1], "--menu") != 0) {
    printf("[um][warn] unknown arg: %s\n", argv[1]);
    usage(argv[0]);
  }

  run_menu();
  return 0;
}
