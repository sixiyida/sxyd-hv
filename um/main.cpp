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

  // TODO: 将后续队列生产者逻辑接入这里（填充描述符、推进 head 等）。

  printf("[um] handshake OK, continuing to hide HV pages...\n");
  fflush(stdout);

  // 3) 简单写入一个 NOP 条目，验证队列消费
  auto* qhdr = hv::sq_header(queue);
  auto* qent = hv::sq_entries(queue);
  qhdr->head = 0;
  qhdr->tail = 0;

  // 在队列内预留一块数据区（第二页）作为读写缓冲，避免覆盖描述符
  uint8_t* scratch = reinterpret_cast<uint8_t*>(reinterpret_cast<uint8_t*>(queue) + 0x1000);
  ZeroMemory(scratch, 0x200);

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

  // 4) 准备 virt 测试缓冲
  auto* virt_src = scratch + 0x100; // 0x80 bytes
  auto* virt_dst = scratch + 0x180; // 0x80 bytes
  for (size_t i = 0; i < 0x80; ++i)
    virt_src[i] = static_cast<uint8_t>(i);
  ZeroMemory(virt_dst, 0x80);

  // write_virt: src=virt_src (current), dst=virt_dst (same cr3)
  ZeroMemory(&qent[1], sizeof(hv::shared_queue_entry));
  qent[1].cmd    = static_cast<uint32_t>(hv::shared_queue_cmd::write_virt);
  qent[1].status = static_cast<uint32_t>(hv::shared_queue_entry_status::pending);
  qent[1].cr3    = 0; // 0 表示当前 cr3
  qent[1].gva    = reinterpret_cast<uint64_t>(virt_dst); // 目标 VA
  qent[1].gpa    = reinterpret_cast<uint64_t>(virt_src); // 源 VA
  qent[1].size   = 0x80;

  // read_virt: src=virt_dst (target), dst=virt_dst2 (current)
  auto* virt_dst2 = scratch + 0x200; // 0x80 bytes
  ZeroMemory(virt_dst2, 0x80);

  ZeroMemory(&qent[2], sizeof(hv::shared_queue_entry));
  qent[2].cmd    = static_cast<uint32_t>(hv::shared_queue_cmd::read_virt);
  qent[2].status = static_cast<uint32_t>(hv::shared_queue_entry_status::pending);
  qent[2].cr3    = 0; // 当前 cr3
  qent[2].gva    = reinterpret_cast<uint64_t>(virt_dst);  // 源 VA
  qent[2].gpa    = reinterpret_cast<uint64_t>(virt_dst2); // 目标 VA
  qent[2].size   = 0x80;

  _mm_mfence();
  qhdr->head = 3; // 发布 3 个条目（nop + write_virt + read_virt）
  _mm_mfence();

  // 在某些环境（尤其 nested/VMware）里，VMX preemption timer 可能不可用或不稳定，
  // 导致 HV 没有新的 VM-exit 来轮询共享队列。这里做一个“kick”：再触发一次同样的 CPUID 握手，
  // 以强制产生 vm-exit，让 HV 立即处理队列。
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

  // 轮询检查 tail 是否前进，验证队列消费
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

  // 5) 验证 EPT 自隐藏是否生效：
  // 注意：通过 shared queue 的 read_virt 是 HV root-mode 直接读物理内存，不经过 EPT，
  // 所以即使 hide 生效也可能依然看到 "MZ"。这里改为查询 EPT 对该 VA 的映射结果。
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

  // 6) 在退出前显式注销共享队列，避免退出后 CR3/页复用导致 HV 继续写旧队列
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

  printf("[um] exiting, press Enter.\n");
  fflush(stdout);
  getchar();
}

