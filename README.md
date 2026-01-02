# hv + um (Windows VT-x research hypervisor)

This repository contains:

- **`hv/`**: a Windows x64 kernel-mode driver (`hv.sys`) that virtualizes the system using Intel VT-x/VMX.
- **`um/`**: a user-mode console tool (`um.exe`) used to interact with the hypervisor for demos/diagnostics.

> **Disclaimer:** This is a low-level research project. Loading a custom hypervisor driver can crash your system (BSOD), break debugging tools, and may violate your organization’s policies. Use at your own risk on a test machine/VM snapshot.

## How it works (high level)

Unlike a typical driver+user app pair, `um` does **not** talk to `hv.sys` via device objects / IOCTLs.

Instead, `hv` intercepts **CPUID** VM-exits:

- `um` performs a **CPUID handshake** to check whether the hypervisor is present (signature: `fr0g`).
- For control/data-plane operations, `um` allocates a small **shared queue** in user memory, registers it via CPUID, writes commands into the queue, then “kicks” the hypervisor by executing CPUID again to force a VM-exit.
- `hv` processes the queue in VM-exit context (root-mode) and writes results back into the queue entry.

This approach keeps the surface area small (no device interface), but also means:

- `um` must run on the same machine where `hv.sys` is loaded.
- If `hv.sys` is not running, `um` will report `HV not running`.

## Requirements

- **CPU**: Intel CPU with VT-x/VMX support (VMXON must succeed).
- **Firmware**: VT-x enabled in BIOS/UEFI.
- **OS**: Windows x64.
- **Build tools**:
  - Visual Studio (solution is VS2019-format, but newer VS works).
  - Windows 10/11 WDK (the driver project uses `WindowsKernelModeDriver10.0` toolset).

### Notes about Hyper-V / VBS

If Hyper-V / VBS / HVCI is enabled, VMX may already be owned by the platform hypervisor and `hv` may fail to virtualize the system. If `hv.sys` prints `VMXON failed` or `Failed to virtualize system`, try disabling those features on a test machine.

## Build

Open `hv.sln` and build:

- **`hv` (Driver, x64)**: produces `hv.sys`
- **`um` (Console app, x64)**: produces `um.exe`

Build outputs are configured into the solution-local `build/` directory:

- `build/hv/release/hv/hv.sys`
- `build/um/release/um.exe`

(Also see `build/*/debug/` for Debug builds.)

## Install / Load `hv.sys`

You can load the driver using your preferred method (Service Control Manager, OSR Driver Loader, etc.).

Example using `sc` (Admin shell):

```bat
sc create hv type= kernel start= demand binPath= "C:\path\to\hv.sys"
sc start hv
```

To stop/remove:

```bat
sc stop hv
sc delete hv
```

### Test signing

The driver project is configured for **test-signing**. On many systems you will need to enable test-signing mode and reboot before Windows will load an unsigned/test-signed driver.

## Run `um.exe`

`um` is an interactive console tool (recommended):

```bat
um.exe --menu
```

Other commands:

- `um.exe --devirt-all`  
  Request global devirtualization via the shared-queue path. This is useful **before unloading `hv.sys`**, especially when EPT self-hide is enabled.
- `um.exe --demo`  
  Runs a legacy shared-queue demo (read/write phys/virt).
- `um.exe --bench-tsc`  
  Benchmarks CPUID-handshake latency using `RDTSC/RDTSCP`.
- `um.exe --diag-tsc`  
  Dumps recent TSC compensation diagnostics via shared-queue (no hypercall).
- `um.exe --check-hide`  
  Checks whether EPT self-hide works for `hv.sys`, and whether shared-queue pages are hidden from other CR3 contexts.

## Recommended unload flow (important)

When the hypervisor is active, unloading the driver can be sensitive (especially with EPT hiding features enabled).

Recommended sequence:

1. Run `um.exe --devirt-all` and keep it open until it reports completion.
2. Stop/unload `hv.sys` using SCM (or your loader).

## Project layout

- `hv/`:
  - VMX bring-up and VCPU management
  - VM-exit handlers
  - EPT code (including experimental self-hide / queue-hide)
  - shared-queue registry + command processor
- `um/`:
  - CPUID handshake + shared-queue session helper
  - demo/bench/diagnostic commands
- `extern/ia32-doc/`: generated Intel SDM header helpers (IA-32/VMX definitions)

## License

MIT (see `LICENSE`).


