#include <iostream>
#include <cstdio>

#include "hv.h"
#include "dumper.h"

int main() {
  if (!hv::is_hv_running()) {
    printf("[um] HV not running.\n");
    printf("Press Enter to exit.\n");
    getchar();
    return 0;
  }

  // 1) 分配并锁定一块共享队列内存（示例：8KB，足够放元数据+ring）
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

  // 填充队列页，避免未触摸导致的懒分配
  memset(queue, 0xA5, queue_size);

  // 2) 进行 CPUID 握手注册
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
    // 尝试读取 HV 日志
    uint32_t count = 64;
    hv::logger_msg msgs[64];
    hv::flush_logs(count, msgs);
    for (uint32_t i = 0; i < count; ++i)
      printf("[HVLOG][%I64u][CPU=%u] %s\n", msgs[i].id, msgs[i].aux, msgs[i].data);
    VirtualUnlock(queue, queue_size);
    VirtualFree(queue, 0, MEM_RELEASE);
    printf("Press Enter to exit.\n");
    getchar();
    return 0;
  }

  printf("[um] queue handshake: signature=%llX status=%u pages=%u magic_echo=%llX\n",
    hs.signature, static_cast<uint32_t>(hs.status), hs.page_count, hs.echoed_magic);
  fflush(stdout);

  // 再做一次轻量 ping，确认 hypercall 路径仍可用
  auto const ping_sig = hv::ping();
  printf("[um] ping after handshake => 0x%llX (expect 0x%llX)\n",
    ping_sig, hv::hypervisor_signature);
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

  // TODO: 将后续队列生产者逻辑接入这里（填充描述符、推进 head 等）。

  printf("[um] handshake OK, continuing to hide HV pages...\n");
  fflush(stdout);

  // 3) 简单写入一个 NOP 条目，验证队列消费
  auto* qhdr = hv::sq_header(queue);
  auto* qent = hv::sq_entries(queue);
  qhdr->head = 0;
  qhdr->tail = 0;

  // 清理首个条目，避免 0xA5 填充影响日志
  ZeroMemory(&qent[0], sizeof(hv::shared_queue_entry));
  qent[0].cmd    = static_cast<uint32_t>(hv::shared_queue_cmd::nop);
  qent[0].status = static_cast<uint32_t>(hv::shared_queue_entry_status::pending);
  qent[0].size   = 0;
  qent[0].flags  = 0;
  qent[0].aux    = 0;

  // 发布 head=1
  _mm_mfence();
  qhdr->head = 1;
  _mm_mfence();

  auto const hv_base = static_cast<uint8_t*>(hv::get_hv_base());
  auto const hv_size = 0x64000;

  // hide the hypervisor
  size_t hide_fail = 0;
  hv::for_each_cpu([&](uint32_t) {
    for (size_t i = 0; i < hv_size; i += 0x1000) {
      auto const virt = hv_base + i;
      auto const phys = hv::get_physical_address(0, virt);

      if (!phys) {
        printf("[um][warn] failed to get physical address for 0x%p.\n", virt);
        continue;
      }

      if (!hv::hide_physical_page(phys >> 12)) {
        ++hide_fail;
        printf("[um][warn] failed to hide page: 0x%p (pfn=0x%llX).\n", virt, phys >> 12);
      }
    }
  });
  printf("[um] hide pages done. fail count=%zu\n", hide_fail);
  fflush(stdout);

  printf("Pinged the hypervisor! Flushing logs...\n");
  fflush(stdout);

  FILE* file = nullptr;
  fopen_s(&file, "hvlog.txt", "a");
  if (!file) {
    printf("[um][err] failed to open hvlog.txt for append.\n");
  }

  while (!GetAsyncKeyState(VK_RETURN)) {
    // flush the logs
    uint32_t count = 512;
    hv::logger_msg msgs[512];
    hv::flush_logs(count, msgs);

    // print the logs
    for (uint32_t i = 0; i < count; ++i) {
      printf("[%I64u][CPU=%u] %s\n", msgs[i].id, msgs[i].aux, msgs[i].data);
      if (file)
        fprintf(file, "[%I64u][CPU=%u] %s\n", msgs[i].id, msgs[i].aux, msgs[i].data);
    }

    if (file)
      fflush(file);

    // 轮询检查 tail 是否前进，验证 NOP 已被消费
    static bool entry0_reported = false;
    auto const tail = qhdr->tail;
    if (!entry0_reported &&
        tail > 0 &&
        qent[0].status == static_cast<uint32_t>(hv::shared_queue_entry_status::done)) {
      printf("[um] queue entry 0 done, tail=%u\n", tail);
      entry0_reported = true;
    }

    Sleep(200);
  }

  if (file)
    fclose(file);

  hv::for_each_cpu([](uint32_t) {
    hv::remove_all_mmrs();
  });

  printf("[um] exiting, press Enter.\n");
  fflush(stdout);
  getchar();
}

