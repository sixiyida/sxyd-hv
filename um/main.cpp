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
  printf("  %s --devirt-all    # request global devirtualization via shared-queue (useful before unloading hv.sys when EPT self-hide is enabled)\n", exe);
  printf("  %s --demo          # run the shared-queue demo (legacy behavior)\n", exe);
  printf("  %s --bench-tsc     # benchmark CPUID-handshake latency using RDTSC/RDTSCP\n", exe);
  printf("  %s --diag-tsc      # dump recent TSC compensation diagnostics via shared-queue (no hypercall)\n", exe);
  printf("  %s --check-hide    # check whether hv.sys EPT self-hide works, and whether shared-queue pages are hidden from other CR3\n", exe);
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

  hv::shared_queue_session sq;
  if (!sq.open(/*queue_size=*/0x2000, /*magic=*/0xD1A6D1A6D1A6D1A6ull, /*seed=*/0xF00DF00DF00DF00Dull)) {
    auto const hs = sq.last_handshake();
    printf("[um][err] shared-queue open failed: signature=0x%llX status=%u pages=%u\n",
      static_cast<unsigned long long>(hs.signature),
      static_cast<uint32_t>(hs.status),
      hs.page_count);
    return;
  }

  // Output buffer: one page (HV side enforces <= 0x1000 for now).
  constexpr uint32_t out_size = 0x1000;
  auto* out = static_cast<uint8_t*>(
    VirtualAlloc(nullptr, out_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
  if (!out) {
    printf("[um][err] VirtualAlloc(out) failed (gle=0x%08X).\n", GetLastError());
    return;
  }
  memset(out, 0, out_size);

  hv::shared_queue_entry e{};
  e.cmd  = static_cast<uint32_t>(hv::shared_queue_cmd::tsc_diag_dump);
  e.gva  = reinterpret_cast<uint64_t>(out);
  e.size = out_size;

  if (!sq.submit(e)) {
    printf("[um][err] diag dump not completed (status=0x%08X).\n", e.status);
  } else {
    auto const* hdr = reinterpret_cast<hv::tsc_diag_dump_header const*>(out);
    printf("[um][diag] tsc_diag_dump: newest_seq=%llu count=%u entry_size=%u (aux=%llu newest=%llu)\n",
      static_cast<unsigned long long>(hdr->newest_seq),
      hdr->count,
      hdr->entry_size,
      static_cast<unsigned long long>(e.aux),
      static_cast<unsigned long long>(e.reserved));

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
}

static void action_diag_exits() {
  if (!ensure_hv_running())
    return;

  hv::shared_queue_session sq;
  if (!sq.open(/*queue_size=*/0x2000, /*magic=*/0xE17157A7E17157A7ull, /*seed=*/0x5151515151515151ull)) {
    auto const hs = sq.last_handshake();
    printf("[um][err] shared-queue open failed: signature=0x%llX status=%u pages=%u\n",
      static_cast<unsigned long long>(hs.signature),
      static_cast<uint32_t>(hs.status),
      hs.page_count);
    return;
  }

  // Output buffer (one page).
  constexpr uint32_t out_size = 0x1000;
  auto* out = static_cast<uint8_t*>(
    VirtualAlloc(nullptr, out_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
  if (!out) {
    printf("[um][err] VirtualAlloc(out) failed (gle=0x%08X).\n", GetLastError());
    return;
  }
  memset(out, 0, out_size);

  auto do_dump = [&](hv::exit_stats_dump& dst) -> bool {
    memset(out, 0, out_size);

    hv::shared_queue_entry e{};
    e.cmd  = static_cast<uint32_t>(hv::shared_queue_cmd::exit_stats_dump);
    e.gva  = reinterpret_cast<uint64_t>(out);
    e.size = out_size;

    if (!sq.submit(e)) {
      printf("[um][err] exit stats dump not completed (status=0x%08X).\n", e.status);
      return false;
    }

    dst = *reinterpret_cast<hv::exit_stats_dump const*>(out);
    return true;
  };

  hv::exit_stats_dump a{}, b{};
  if (!do_dump(a)) {
    VirtualFree(out, 0, MEM_RELEASE);
    return;
  }

  // Sample delta over ~1 second to identify ongoing VM-exit sources.
  Sleep(1000);

  if (!do_dump(b)) {
    VirtualFree(out, 0, MEM_RELEASE);
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
}

static void action_devirt_all() {
  if (!ensure_hv_running())
    return;

  printf("[um] Requesting global devirtualization via shared queue...\n");
  fflush(stdout);

  hv::shared_queue_session sq;
  if (!sq.open()) {
    auto const hs = sq.last_handshake();
    printf("[um][err] shared-queue open failed: signature=0x%llX status=%u pages=%u\n",
      static_cast<unsigned long long>(hs.signature),
      static_cast<uint32_t>(hs.status),
      hs.page_count);
    return;
  }

  {
    auto const hs = sq.last_handshake();
    printf("[um] queue handshake: signature=0x%llX status=%u pages=%u magic_echo=0x%llX\n",
      static_cast<unsigned long long>(hs.signature),
      static_cast<uint32_t>(hs.status),
      hs.page_count,
      static_cast<unsigned long long>(hs.echoed_magic));
  }

  hv::shared_queue_entry e{};
  e.cmd = static_cast<uint32_t>(hv::shared_queue_cmd::devirt_all);
  if (!sq.submit(e)) {
    printf("[um][err] devirt_all not completed (status=0x%08X).\n", e.status);
    return;
  }

  // Kick all CPUs to force immediate VM-exits and complete devirtualization deterministically.
  // Rationale:
  // - devirt_all sets a global stop flag in the HV (root-mode).
  // - each logical processor devirtualizes on its NEXT VM-exit.
  // - on multi-core (and especially in idle), waiting for timers can race with driver unload.
  printf("[um] Forcing a VM-exit on each CPU (CPUID) to complete devirtualization...\n");
  fflush(stdout);

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
}

static int action_shared_queue_demo() {
  if (!ensure_hv_running()) {
    wait_enter();
    return 0;
  }

  hv::shared_queue_session sq;
  if (!sq.open()) {
    auto const hs = sq.last_handshake();
    printf("[um][err] shared-queue open failed: signature=%llX status=%u pages=%u\n",
      static_cast<unsigned long long>(hs.signature),
      static_cast<uint32_t>(hs.status),
      hs.page_count);
    printf("Press Enter to exit.\n");
    getchar();
    return 0;
  }

  {
    auto const hs = sq.last_handshake();
    printf("[um] queue handshake: signature=%llX status=%u pages=%u magic_echo=%llX\n",
      static_cast<unsigned long long>(hs.signature),
      static_cast<uint32_t>(hs.status),
      hs.page_count,
      static_cast<unsigned long long>(hs.echoed_magic));
  }

  // 1) Validate queue consumption with a NOP
  hv::shared_queue_entry nop{};
  nop.cmd = static_cast<uint32_t>(hv::shared_queue_cmd::nop);
  if (!sq.submit(nop)) {
    printf("[um][err] nop not completed (status=0x%08X).\n", nop.status);
    wait_enter();
    return 0;
  }
  printf("[um] nop done.\n");

  // 2) Small virt write/read demo using plain user buffers (not queue memory)
  constexpr size_t scratch_size = 0x1000;
  auto* scratch = static_cast<uint8_t*>(
    VirtualAlloc(nullptr, scratch_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
  if (!scratch) {
    printf("[um][err] VirtualAlloc(scratch) failed (gle=0x%08X).\n", GetLastError());
    wait_enter();
    return 0;
  }
  ZeroMemory(scratch, scratch_size);

  auto* virt_src  = scratch + 0x100;
  auto* virt_dst  = scratch + 0x200;
  auto* virt_dst2 = scratch + 0x300;
  for (size_t i = 0; i < 0x80; ++i)
    virt_src[i] = static_cast<uint8_t>(i);
  ZeroMemory(virt_dst, 0x80);
  ZeroMemory(virt_dst2, 0x80);

  auto const w = sq.write_virtual(/*target_cr3=*/0, virt_dst, virt_src, 0x80);
  auto const r = sq.read_virtual(/*target_cr3=*/0, virt_dst2, virt_dst, 0x80);
  printf("[um] write_virtual=%zu read_virtual=%zu\n", w, r);
  printf("[um] read_virt buffer (first 32 bytes):\n  ");
  for (size_t i = 0; i < 32; ++i)
    printf("%02X ", virt_dst2[i]);
  printf("\n");

  // 5) Validate whether EPT self-hide is effective:
  // NOTE: shared-queue read_virt reads physical memory in root-mode and does NOT go through EPT,
  // so you may still see "MZ" even if hide is effective. We query EPT mapping instead.
  void* hv_base = nullptr;
  uint32_t hv_size = 0;
  if (find_loaded_driver("hv.sys", hv_base, hv_size)) {
    printf("[um] hv.sys base=%p size=0x%X\n", hv_base, hv_size);

    hv::shared_queue_entry q{};
    q.cmd = static_cast<uint32_t>(hv::shared_queue_cmd::query_ept_map);
    q.cr3 = 0;
    q.gva = reinterpret_cast<uint64_t>(hv_base);
    if (sq.submit(q)) {
      auto const orig_pfn   = q.gpa;
      auto const mapped_pfn = q.aux;
      auto const dummy_pfn  = q.reserved;
      printf("[um] EPT map for hv.sys base: orig_pfn=0x%llX mapped_pfn=0x%llX dummy_pfn=0x%llX\n",
        orig_pfn, mapped_pfn, dummy_pfn);
    } else {
      printf("[um][warn] EPT map query failed (status=0x%08X).\n", q.status);
    }
  } else {
    printf("[um][warn] failed to locate hv.sys in loaded module list; skip self-hide check.\n");
  }

  VirtualFree(scratch, 0, MEM_RELEASE);

  printf("[um] exiting.\n");
  fflush(stdout);
  wait_enter();
  return 0;
}

static uint64_t parse_u64(char const* s) {
  if (!s)
    return 0;
  // accepts 123, 0x123
  return std::strtoull(s, nullptr, 0);
}

static bool set_affinity_cpu(uint32_t cpu_idx) {
  if (cpu_idx >= 64) {
    printf("[um][err] cpu index too large for affinity mask: %u\n", cpu_idx);
    return false;
  }
  auto const mask = 1ull << cpu_idx;
  auto const prev = SetThreadAffinityMask(GetCurrentThread(), mask);
  if (!prev) {
    printf("[um][err] SetThreadAffinityMask failed (gle=0x%08X).\n", GetLastError());
    return false;
  }
  return true;
}

// Child: run on a specific CPU, register a queue for THIS process, and check whether the given PFN
// is mapped to the dummy page in the current VCPU's EPT.
static int action_check_queue_hidden(uint64_t const target_pfn, uint32_t const cpu_idx) {
  if (!ensure_hv_running())
    return 1;

  if (!set_affinity_cpu(cpu_idx))
    return 1;

  hv::shared_queue_session sq;
  if (!sq.open()) {
    auto const hs = sq.last_handshake();
    printf("[um][child][err] shared-queue open failed: signature=%llX status=%u pages=%u\n",
      static_cast<unsigned long long>(hs.signature),
      static_cast<uint32_t>(hs.status),
      hs.page_count);
    return 1;
  }

  hv::shared_queue_entry e{};
  e.cmd = static_cast<uint32_t>(hv::shared_queue_cmd::query_ept_gpa);
  e.gpa = (target_pfn << 12);
  if (!sq.submit(e)) {
    printf("[um][child][err] query_ept_gpa failed (status=0x%08X).\n", e.status);
    return 1;
  }

  auto const orig_pfn   = e.gpa;
  auto const mapped_pfn = e.aux;
  auto const dummy_pfn  = e.reserved;
  bool const hidden = (dummy_pfn != 0 && mapped_pfn == dummy_pfn);

  printf("[um][child] target_pfn=0x%llX => ept_mapped_pfn=0x%llX dummy_pfn=0x%llX => hidden=%s\n",
    orig_pfn, mapped_pfn, dummy_pfn, hidden ? "true" : "false");
  return hidden ? 0 : 2;
}

static int action_check_hide() {
  if (!ensure_hv_running())
    return 1;

  // Pin to CPU0 so parent/child observe the same VCPU EPT instance.
  uint32_t cpu_idx = 0;
  if (!set_affinity_cpu(cpu_idx))
    return 1;

  hv::shared_queue_session sq;
  if (!sq.open()) {
    auto const hs = sq.last_handshake();
    printf("[um][err] shared-queue open failed: signature=%llX status=%u pages=%u\n",
      static_cast<unsigned long long>(hs.signature),
      static_cast<uint32_t>(hs.status),
      hs.page_count);
    return 1;
  }

  // 1) hv.sys self-hide check (same as demo)
  void* hv_base = nullptr;
  uint32_t hv_size = 0;
  if (find_loaded_driver("hv.sys", hv_base, hv_size)) {
    hv::shared_queue_entry map{};
    map.cmd = static_cast<uint32_t>(hv::shared_queue_cmd::query_ept_map);
    map.cr3 = 0;
    map.gva = reinterpret_cast<uint64_t>(hv_base);

    if (sq.submit(map)) {
      auto const orig_pfn   = map.gpa;
      auto const mapped_pfn = map.aux;
      auto const dummy_pfn  = map.reserved;

      // IMPORTANT:
      // In "read-hide/exec-ok" mode (EPT hook toggling), the *current* mapped_pfn depends on
      // the last access type (execute vs read). So mapped_pfn==dummy is NOT a reliable indicator.
      // Instead, query whether this PFN is EPT-hooked and whether the hook read_pfn is dummy.
      printf("[um] hv.sys EPT (current): orig_pfn=0x%llX mapped_pfn=0x%llX dummy_pfn=0x%llX\n",
        orig_pfn, mapped_pfn, dummy_pfn);

      hv::shared_queue_entry hook{};
      hook.cmd = static_cast<uint32_t>(hv::shared_queue_cmd::query_ept_hook_gpa);
      hook.gpa = (orig_pfn << 12);

      if (sq.submit(hook)) {
        auto const hooked_pfn = hook.gpa;
        auto const hook_read  = hook.aux;
        auto const hook_exec  = hook.reserved;
        auto const hook_dummy = hook.cr3;
        bool const hooked = (hook_read != 0 || hook_exec != 0);
        bool const self_hide = (hooked && hook_dummy != 0 && hook_read == hook_dummy);
        printf("[um] hv.sys EPT hook: hooked=%s hooked_pfn=0x%llX read_pfn=0x%llX exec_pfn=0x%llX dummy_pfn=0x%llX => self_hide=%s\n",
          hooked ? "true" : "false", hooked_pfn, hook_read, hook_exec, hook_dummy, self_hide ? "true" : "false");
      } else {
        printf("[um][warn] hv.sys hook check failed (status=0x%08X).\n", hook.status);
      }
    } else {
      printf("[um][warn] hv.sys self-hide check failed (status=0x%08X).\n", map.status);
    }
  } else {
    printf("[um][warn] failed to locate hv.sys; skip hv.sys self-hide check.\n");
  }

  // 2) Query PFN of OUR queue page via query_ept_map (so we can test it from a different CR3)
  hv::shared_queue_entry qmap{};
  qmap.cmd = static_cast<uint32_t>(hv::shared_queue_cmd::query_ept_map);
  qmap.cr3 = 0;
  qmap.gva = reinterpret_cast<uint64_t>(sq.raw_queue());

  if (!sq.submit(qmap)) {
    printf("[um][err] failed to query queue PFN (status=0x%08X).\n", qmap.status);
    return 1;
  }

  uint64_t const queue_pfn = qmap.gpa; // orig PFN
  printf("[um] queue base=%p => pfn=0x%llX\n", sq.raw_queue(), queue_pfn);

  // 3) Spawn a child process pinned to the same CPU to check whether that PFN is hidden
  char exe_path[MAX_PATH] = {};
  GetModuleFileNameA(nullptr, exe_path, MAX_PATH);

  char cmdline[512] = {};
  std::snprintf(cmdline, sizeof(cmdline),
    "\"%s\" --check-queue-hidden 0x%llX %u", exe_path, queue_pfn, cpu_idx);

  STARTUPINFOA si{};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi{};
  if (!CreateProcessA(nullptr, cmdline, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
    printf("[um][err] CreateProcess failed (gle=0x%08X).\n", GetLastError());
    return 1;
  }

  WaitForSingleObject(pi.hProcess, 5000);
  DWORD exit_code = 0;
  GetExitCodeProcess(pi.hProcess, &exit_code);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);

  printf("[um] child exit code=%lu (0=hidden, 2=not-hidden)\n", exit_code);
  return 0;
}

static void run_menu() {
  for (;;) {
    printf("\n========== hv um menu ==========\n");
    printf("1) ping (check if HV is running)\n");
    printf("2) shared-queue demo\n");
    printf("3) devirt-all (request global devirtualization via shared-queue; use before unloading hv.sys when self-hide is enabled)\n");
    printf("4) bench-tsc (measure CPUID-handshake latency via RDTSC/RDTSCP)\n");
    printf("5) diag-tsc (dump TSC compensation diagnostics via shared-queue)\n");
    printf("6) diag-exits (dump VM-exit/MSR statistics via shared-queue)\n");
    printf("7) check-hide (hv.sys self-hide + shared-queue EPT hide check)\n");
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
      action_shared_queue_demo();
      break;
    case 3:
      action_devirt_all();
      wait_enter();
      break;
    case 4:
      action_bench_tsc();
      wait_enter();
      break;
    case 5:
      action_diag_tsc();
      wait_enter();
      break;
    case 6:
      action_diag_exits();
      wait_enter();
      break;
    case 7:
      action_check_hide();
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

  // internal: child helper for shared-queue hide detection
  if (argc >= 4 && strcmp(argv[1], "--check-queue-hidden") == 0) {
    uint64_t const pfn = parse_u64(argv[2]);
    uint32_t const cpu = static_cast<uint32_t>(parse_u64(argv[3]));
    return action_check_queue_hidden(pfn, cpu);
  }

  if (argc >= 2 && strcmp(argv[1], "--check-hide") == 0) {
    return action_check_hide();
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
