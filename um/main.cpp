#include <iostream>
#include <cstdio>
#include <string>
#include <cstring>

#include "hv.h"
#include "dumper.h"

static void usage(char const* const exe) {
  printf("usage:\n");
  printf("  %s --menu         # interactive menu (recommended)\n", exe);
  printf("  %s --devirt-all    # run hypercall_unload on every CPU (useful before unloading hv.sys when EPT self-hide is enabled)\n", exe);
  printf("  %s --demo          # run the shared-queue demo (legacy behavior)\n", exe);
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

  // Kick HV: repeat handshake to force a VM-exit, then it will process the queue.
  auto const ks = hv::queue_handshake(req);
  printf("[um] kick result: signature=0x%llX status=%u pages=%u magic_echo=0x%llX\n",
    ks.signature, static_cast<uint32_t>(ks.status), ks.page_count, ks.echoed_magic);

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
