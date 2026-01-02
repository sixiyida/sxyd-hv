#include "timing.h"
#include "vcpu.h"
#include "vmx.h"
#include "logger.h"

#include <stdint.h>
#include <ntdef.h>

namespace hv {

// Enable/disable TSC compensation globally.
// If disabled, we keep VMCS TSC offset at 0 to avoid guest time drift/jitter.
#if !defined(HV_ENABLE_TSC_COMPENSATION)
#define HV_ENABLE_TSC_COMPENSATION 1
#endif

// Scale factor for TSC compensation to reduce the chance of guest-visible TSC going backwards.
// Default: 1/2 (50%). You can override at build time with HV_TSC_COMP_NUM / HV_TSC_COMP_DEN.
#if !defined(HV_TSC_COMP_NUM)
#define HV_TSC_COMP_NUM 1
#endif
#if !defined(HV_TSC_COMP_DEN)
#define HV_TSC_COMP_DEN 2
#endif
static_assert(HV_TSC_COMP_DEN != 0, "HV_TSC_COMP_DEN must be non-zero");

// Minimum amount of guest-visible TSC progress (in cycles) to preserve on each VM-exit where
// compensation is applied. This is a safety valve: stronger compensation lowers measured deltas
// (e.g. UM bench), but can destabilize timekeeping if it makes time appear to "stall".
//
// Recommended for bench tuning: 100..300.
#if !defined(HV_TSC_MIN_ADVANCE)
#define HV_TSC_MIN_ADVANCE 200
#endif

// Legacy behavior: when we decide not to hide the overhead for an exit, reset TSC offset to 0.
// This can create guest-visible time discontinuities (and large spikes in user-mode benches
// that measure via RDTSCP). Default: keep the offset to avoid jitter/spikes.
#if !defined(HV_TSC_RESET_ON_NOHIDE)
#define HV_TSC_RESET_ON_NOHIDE 1
#endif

// Clamp how much we are allowed to "eat" per VM-exit (cycles). This prevents sudden large time steps.
#if !defined(HV_TSC_MAX_EAT_PER_EXIT)
#define HV_TSC_MAX_EAT_PER_EXIT 50000
#endif

// try to hide the vm-exit overhead from being detected through timings
void hide_vm_exit_overhead(vcpu* const cpu, uint64_t const host_entry_tsc) {
  // Safety switch.
  // Keeping a non-zero/ever-changing TSC offset can destabilize Windows timekeeping.
#if !HV_ENABLE_TSC_COMPENSATION
  UNREFERENCED_PARAMETER(host_entry_tsc);
  cpu->tsc_offset = 0;
  cpu->last_guest_tsc = __rdtsc();
  cpu->hide_vm_exit_overhead = false;
  return;
#endif
  //
  // Guest APERF/MPERF values are stored/restored on vm-entry and vm-exit,
  // however, there appears to be a small, yet constant, overhead that occurs
  // when the CPU is performing these stores and loads. This is the case for
  // every MSR, so naturally PERF_GLOBAL_CTRL is affected as well. If it wasn't
  // for this, hiding vm-exit overhead via MSR tricks would be much simpler.
  //

  ia32_perf_global_ctrl_register perf_global_ctrl;
  perf_global_ctrl.flags = cpu->msr_exit_store.perf_global_ctrl.msr_data;

  // make sure the CPU loads the previously stored guest state on vm-entry
  cpu->msr_entry_load.aperf.msr_data = cpu->msr_exit_store.aperf.msr_data;
  cpu->msr_entry_load.mperf.msr_data = cpu->msr_exit_store.mperf.msr_data;
  vmx_vmwrite(VMCS_GUEST_PERF_GLOBAL_CTRL, perf_global_ctrl.flags);

  // account for the constant overhead associated with loading/storing MSRs
  cpu->msr_entry_load.aperf.msr_data -= cpu->vm_exit_mperf_overhead;
  cpu->msr_entry_load.mperf.msr_data -= cpu->vm_exit_mperf_overhead;

  // account for the constant overhead associated with loading/storing MSRs
  if (perf_global_ctrl.en_fixed_ctrn & (1ull << 2)) {
    auto const cpl = current_guest_cpl();

    ia32_fixed_ctr_ctrl_register fixed_ctr_ctrl;
    fixed_ctr_ctrl.flags = __readmsr(IA32_FIXED_CTR_CTRL);

    // This likely needs to be done for additional PMCs for completeness.
    if ((cpl == 0 && fixed_ctr_ctrl.en2_os) || (cpl == 3 && fixed_ctr_ctrl.en2_usr))
      __writemsr(IA32_FIXED_CTR2, __readmsr(IA32_FIXED_CTR2) - cpu->vm_exit_ref_tsc_overhead);
  }  
  
  // this usually occurs for vm-exits that are unlikely to be reliably timed,
  // such as when an exception occurs or if the preemption timer fired
  if (!cpu->hide_vm_exit_overhead) {
    // Not hiding for this exit: keep time stable.
#if HV_TSC_RESET_ON_NOHIDE
    cpu->tsc_offset = 0;
#endif
    auto const host_now_s = static_cast<int64_t>(__rdtsc());
    auto const off_s      = static_cast<int64_t>(cpu->tsc_offset);
    cpu->last_guest_tsc   = static_cast<uint64_t>(host_now_s + off_s);
    return;
  }

  // Dynamic compensation (conservative):
  // Eat only a FRACTION of the measured VM-exit wall time, and clamp the adjustment.
  auto const host_now_s = static_cast<int64_t>(__rdtsc());
  auto const entry_s    = static_cast<int64_t>(host_entry_tsc);
  auto const elapsed_s  = host_now_s - entry_s;

  constexpr int64_t min_advance_s = static_cast<int64_t>(HV_TSC_MIN_ADVANCE);
  int64_t eat_s = 0;
  if (elapsed_s > min_advance_s)
    eat_s = elapsed_s - min_advance_s;

  // Scale down to avoid time drift/stutter on multi-core Windows.
  eat_s = (eat_s * static_cast<int64_t>(HV_TSC_COMP_NUM)) / static_cast<int64_t>(HV_TSC_COMP_DEN);

  if (eat_s < 0)
    eat_s = 0;
  if (eat_s > static_cast<int64_t>(HV_TSC_MAX_EAT_PER_EXIT))
    eat_s = static_cast<int64_t>(HV_TSC_MAX_EAT_PER_EXIT);

  auto new_off_s = static_cast<int64_t>(cpu->tsc_offset) - eat_s;
  auto guest_now_s = host_now_s + new_off_s;

  // Per-core monotonic clamp (minimum progress).
  auto const min_allowed_s = static_cast<int64_t>(cpu->last_guest_tsc) + min_advance_s;
  if (guest_now_s < min_allowed_s) {
    guest_now_s = min_allowed_s;
    new_off_s = guest_now_s - host_now_s;
  }

  cpu->tsc_offset = static_cast<uint64_t>(new_off_s);
  cpu->last_guest_tsc = static_cast<uint64_t>(guest_now_s);

  auto const eat_u = static_cast<uint64_t>(eat_s);
  if (cpu->cumulative_tsc_exit_overhead >= eat_u)
    cpu->cumulative_tsc_exit_overhead -= eat_u;
  else
    cpu->cumulative_tsc_exit_overhead = 0;
}

// measure the overhead of a vm-exit (RDTSC)
uint64_t measure_vm_exit_tsc_overhead() {
  _disable();

  uint64_t lowest_vm_exit_overhead = ~0ull;
  uint64_t lowest_timing_overhead  = ~0ull;

  // perform the measurement 10 times and use the smallest time
  for (int i = 0; i < 10; ++i) {
    _mm_lfence();
    auto start = __rdtsc();
    _mm_lfence();

    _mm_lfence();
    auto end = __rdtsc();
    _mm_lfence();

    auto const timing_overhead = (end - start);

    _mm_lfence();
    start = __rdtsc();
    _mm_lfence();

    // trigger a reliable VM-exit in builds where VMCALL is disabled
    // (CPUID is always intercepted and emulated).
    int regs[4] = {};
    __cpuidex(regs, 0, 0);

    _mm_lfence();
    end = __rdtsc();
    _mm_lfence();

    auto const vm_exit_overhead = (end - start);

    if (vm_exit_overhead < lowest_vm_exit_overhead)
      lowest_vm_exit_overhead = vm_exit_overhead;
    if (timing_overhead < lowest_timing_overhead)
      lowest_timing_overhead = timing_overhead;
  }

  _enable();
  return lowest_vm_exit_overhead - lowest_timing_overhead;
}

// measure the overhead of a vm-exit (CPU_CLK_UNHALTED.REF_TSC)
uint64_t measure_vm_exit_ref_tsc_overhead() {
#if defined(HV_NO_VMCALL)
  return 0;
#endif
  _disable();

  hypercall_input hv_input;
  hv_input.code = hypercall_ping;
  hv_input.key  = hypercall_key;

  ia32_fixed_ctr_ctrl_register curr_fixed_ctr_ctrl;
  curr_fixed_ctr_ctrl.flags = __readmsr(IA32_FIXED_CTR_CTRL);

  ia32_perf_global_ctrl_register curr_perf_global_ctrl;
  curr_perf_global_ctrl.flags = __readmsr(IA32_PERF_GLOBAL_CTRL);

  // enable fixed counter #2
  auto new_fixed_ctr_ctrl = curr_fixed_ctr_ctrl;
  new_fixed_ctr_ctrl.en2_os      = 1;
  new_fixed_ctr_ctrl.en2_usr     = 0;
  new_fixed_ctr_ctrl.en2_pmi     = 0;
  new_fixed_ctr_ctrl.any_thread2 = 0;
  __writemsr(IA32_FIXED_CTR_CTRL, new_fixed_ctr_ctrl.flags);

  // enable fixed counter #2
  auto new_perf_global_ctrl = curr_perf_global_ctrl;
  new_perf_global_ctrl.en_fixed_ctrn |= (1ull << 2);
  __writemsr(IA32_PERF_GLOBAL_CTRL, new_perf_global_ctrl.flags);

  uint64_t lowest_vm_exit_overhead = ~0ull;
  uint64_t lowest_timing_overhead  = ~0ull;

  // perform the measurement 10 times and use the smallest time
  for (int i = 0; i < 10; ++i) {
    _mm_lfence();
    auto start = __readmsr(IA32_FIXED_CTR2);
    _mm_lfence();

    _mm_lfence();
    auto end = __readmsr(IA32_FIXED_CTR2);
    _mm_lfence();

    auto const timing_overhead = (end - start);

    vmx_vmcall(hv_input);

    _mm_lfence();
    start = __readmsr(IA32_FIXED_CTR2);
    _mm_lfence();

    vmx_vmcall(hv_input);

    _mm_lfence();
    end = __readmsr(IA32_FIXED_CTR2);
    _mm_lfence();

    auto const vm_exit_overhead = (end - start);

    if (vm_exit_overhead < lowest_vm_exit_overhead)
      lowest_vm_exit_overhead = vm_exit_overhead;
    if (timing_overhead < lowest_timing_overhead)
      lowest_timing_overhead = timing_overhead;
  }

  // restore MSRs
  __writemsr(IA32_PERF_GLOBAL_CTRL, curr_perf_global_ctrl.flags);
  __writemsr(IA32_FIXED_CTR_CTRL, curr_fixed_ctr_ctrl.flags);

  _enable();
  return lowest_vm_exit_overhead - lowest_timing_overhead;
}

// measure the overhead of a vm-exit (IA32_MPERF)
uint64_t measure_vm_exit_mperf_overhead() {
#if defined(HV_NO_VMCALL)
  return 0;
#endif
  _disable();

  hypercall_input hv_input;
  hv_input.code = hypercall_ping;
  hv_input.key  = hypercall_key;

  uint64_t lowest_vm_exit_overhead = ~0ull;
  uint64_t lowest_timing_overhead  = ~0ull;

  // perform the measurement 10 times and use the smallest time
  for (int i = 0; i < 10; ++i) {
    _mm_lfence();
    auto start = __readmsr(IA32_MPERF);
    _mm_lfence();

    _mm_lfence();
    auto end = __readmsr(IA32_MPERF);
    _mm_lfence();

    auto const timing_overhead = (end - start);

    vmx_vmcall(hv_input);

    _mm_lfence();
    start = __readmsr(IA32_MPERF);
    _mm_lfence();

    vmx_vmcall(hv_input);

    _mm_lfence();
    end = __readmsr(IA32_MPERF);
    _mm_lfence();

    auto const vm_exit_overhead = (end - start);

    if (vm_exit_overhead < lowest_vm_exit_overhead)
      lowest_vm_exit_overhead = vm_exit_overhead;
    if (timing_overhead < lowest_timing_overhead)
      lowest_timing_overhead = timing_overhead;
  }

  _enable();
  return lowest_vm_exit_overhead - lowest_timing_overhead;
}

} // namespace hv

