改造方案：基于 VMX Preemption Timer 的无锁共享内存通信（hv 项目）
================================================================

目标
----
- 用 “Pure Ring3 <-> HV Direct Link” 替换/补充现有 VMCALL 同步接口，核心是 VMX 抢占定时器驱动的 SPSC 无锁队列。
- 保留现有 hypercall 作为回退/对照（首阶段并存），逐步迁移主要数据通路。
- 重点关注：安全性（指针/CR3 校验）、性能（VMEXIT 频率）、隐蔽性（计时抖动控制）、健壮性（缺页/错误路径）。

当前基线（hv 仓库能力）
------------------------
- 已有：CR3 读取、gva->hva/gpa 翻译、读写虚/物理、TSC offset/VMX timer 框架（`handle_vmx_preemption` 空实现）。
- 通信：同步 VMCALL 分发在 `exit-handlers.cpp::emulate_vmcall`，用户态封装在 `um/hv.h`。
- 缺口：无 CPUID 握手、无共享内存注册、无队列协议、无 VMX timer 驱动循环。

总体实施路线（3 阶段）
----------------------
1) 最小可用版（并存阶段）
   - 新增 CPUID 握手，注册用户态共享内存（SPSC ring 元数据 + 数据区），支持跨页。
   - 在 `handle_vmx_preemption` 增加轮询逻辑，初期仅支持 READ/WRITE（物理/虚拟）两类命令。
   - VMX timer 周期固定保守值；空队列可 soft-disable（preemption_timer=~0）降低开销。
   - 用户态：分配并 VirtualLock 共享内存，填元数据，触发 CPUID 交付队列 VA。
   - 保留 VMCALL，便于 A/B 对照。

2) 功能扩展与健壮性
   - 扩展命令：query_cr3、get_phys_addr、缺页回填（4K 拷贝）、flush_logs/telemetry。
   - 队列协议完善：长度/对齐校验、状态码、错误返回、反压（队列满时返回 BUSY）。
   - 安全校验：最大 size 上限、VA 对齐/页跨越处理、CR3 白名单（来自握手包）、物理访问窗口限制。
   - VMX timer 自适应：空队列指数回退，繁忙时收敛到低延迟；批处理队列项减少 VMEXIT 次数。
   - 用户态：Unicorn 缺页回调对接队列；增加阻塞/重试与超时处理。

3) 调优与收尾
   - 性能/隐蔽性：调整 timer 周期、批处理上限、TSC offset 配合；测量 VMEXIT 抖动与吞吐。
   - 稳定性：长时间压力测试、异常路径验证（页缺失/非法指针/CR3 失效）。
   - 可选：关闭/隐藏 VMCALL 主通路，仅保留后门或调试开关。

技术方案细节
------------
### 1. 握手与共享内存注册
- 用户态：
  - 分配队列页（建议至少 2*4K：metadata+ring），VirtualLock 固定；记录 VA。若需要更高稳定性，可由内核侧分配非分页池并映射给 R3（权衡暴露面）。
  - 执行特定 CPUID（leaf 0x1337, subleaf 0），RAX=magic，RBX=队列 VA，RCX=大小，RDX=校验/密钥。
- HV：
  - 拦截该 CPUID：读取寄存器参数，走 guest CR3 做 PML4→PT 翻译，校验连续页/跨页映射，缓存页帧列表。
  - 维护 HashTable<CR3, QueueContext>（可再细分到 vCPU 上下文），存储：HPA 列表、magic/seed/version、队列尺寸、状态。
  - 每次轮询前读取元数据 magic/version 校验，必要时再做页头 CRC/seed 校验；不符则停用通道并要求重握手。
  - 可要求 hypercall_key 等价字段在握手提供，作为最小鉴权。

### 2. 队列协议（SPSC，Virtio 风格简化）
- 元数据：head/tail（生产者递增，消费者递增），size=2^n；状态位 DONE/BUSY/ERR；head/tail 分离 cacheline（alignas(64)）防止 false sharing。
- 描述符：{cmd, cr3, gva/pa, size, flags, status, aux/error}，按 64B 对齐。可选 XOR/rolling-key 混淆描述符与 payload，降低内存特征（元数据 head/tail 可明文）。
- 写入规则（R3 端）：
  - 支持批处理：先写入多条描述符，再一次性推进 head（store-release）。
  - 检查 (head - tail) < ring_size，否则等待/返回 BUSY。
  - 填命令后发布 head；自旋等待 status 变 DONE/ERR。
- 读取规则（HV 端）：
  - 轮询时比较 head vs tail；批量取条目，校验 size/对齐/CR3。
  - 执行命令；写 status/aux，再递增 tail（store-release）。批处理减少 VMEXIT 频次。
- 跨页：队列可跨页，HV 端对每次访问做 gva2hva 分段拷贝。

### 3. VMX Preemption Timer 驱动
- 在 VMCS 控制区启用抢占定时器，初期固定值（如触发间隔 ~50–100µs，视硬件 TSC 比率）。
- 自适应两态（忙/打盹）：
  - Busy/Active：发现队列非空后，处理完一批立刻设极短周期（甚至 0），或在一次 VMEXIT 内小循环检查若干次（设硬上限时间/迭代防饥饿），使通信延迟快速收敛。
  - Dozing：连续 N 次空队列后才开始指数回退周期，直到上限，必要时 soft-disable（preemption_timer=~0）。
- 处理时批量消费 N 条（时间/计数上限），减少 VMEXIT 次数；继续配合 TSC offset 降低计时侧信道。

### 4. 命令集（建议顺序落地）
1) READ_VIRT / WRITE_VIRT：使用现有 `gva2hva`/跨页拷贝，CR3 可选指定。
2) READ_PHYS / WRITE_PHYS：限制可访问范围；对齐校验。
3) GET_PHYS_ADDR：返回翻译结果，供用户态建立页表缓存。
4) QUERY_CR3：从内核 EPROCESS 链表获取，或复用现有实现。
5) PAGE_IN (缺页回填)：R3 请求 HV 把物理页拷贝回共享区；size 固定 0x1000，VA 需页对齐；若遇 PTE.P=0，HV 直接返回 ERR_PAGE_NOT_PRESENT。
6) FLUSH_LOGS/TELEMETRY：读取 HV 日志或性能计数。

### 4.1 缺页与重试策略
- HV 手工页表遍历遇 P=0：立即返回 ERR_PAGE_NOT_PRESENT，不做 I/O。
- R3 收到后自行触发缺页（读取该 VA 的 1 字节），让 OS 处理换页，再重试命令；需在 R3 侧做重试节流。

### 5. 安全与健壮性
- 访问限制：size 上限（如 0x200000），物理地址白名单/黑名单，CR3 必须通过握手登记。
- 指针校验：gva2hva 失败时返回 ERR，并写 CR2/错误码；禁止 HV 无限重试。
- 对齐要求：页跨越时分段复制；PAGE_IN 必须页对齐。
- 超时与统计：记录处理时间、错误计数，必要时在 R3 端退避。
- 混淆与特征降低：握手 seed 生成 rolling key，对描述符/payload 做轻量 XOR；元数据 head/tail 可明文以简化同步。
- 物理页漂移检测：每次轮询前验证 magic/version/CRC，不符则停用通道并要求重握手；必要时定期重握手以刷新 HPA。

### 6. 用户态改动
- 队列管理器：封装 enqueue/dequeue、head/tail 维护、自旋/超时策略；支持批处理提交。
- CPUID 握手封装：带 key/magic/seed 的注册函数；异常时回退到 VMCALL。
- Unicorn 集成：在缺页回调里 enqueue PAGE_IN，等待 DONE 后将页映射再继续执行；对 ERR_PAGE_NOT_PRESENT 做一次自触发缺页再重试。
- Shadow Page Table Cache：利用 GET_PHYS_ADDR 维护 VPN->PPN 缓存，同一 CR3 下命中时可直接发 READ_PHYS/WRITE_PHYS（需在 CR3 变更或探测到失效时清空）。
- 压测/调试：提供开关切换 VMCALL vs 新通路，采样延迟/吞吐/错误码分布，用于调 timer 与批处理阈值。

落地步骤与优先级（含估时，开发人日）
------------------------------------
1) CPUID 拦截 + 队列注册（0.5–1d）
   - 新增 CPUID handler、保存 HPA/元数据；用户态握手封装。
2) 队列协议 & 基础命令 READ/WRITE（1–2d）
   - SPSC 读写逻辑、跨页拷贝、错误码；VMX timer 轮询最小实现。
3) 批处理 & 自适应 timer（1d）
   - 空队列回退、忙时收敛；批量处理 N 条减少 VMEXIT。
4) 扩展命令集（query_cr3/get_phys/page_in）（2–3d）
   - 复用现有 hypercall 逻辑改为命令处理；PAGE_IN 固定 4K。
5) 安全/健壮性加固（1–2d）
   - 访问上限、CR3 白名单、错误统计、异常路径不崩溃。
6) 用户态 Unicorn 对接与压测（1–2d）
   - 缺页回调、队列管理、自旋/超时；延迟/吞吐/抖动测试。
7) 调优与收尾（1–2d）
   - TSC offset 配合、timer 参数调节、长稳压测；文档/开关。

测试与验证建议
--------------
- 功能回归：对比 VMCALL 与新通路的读写正确性（同一地址多轮）。
- 压力与稳定：长时间队列读写/缺页回填，观测错误计数与 VMEXIT 率。
- 性能/隐蔽性：采样 RDTSC 抖动、VMEXIT 次数、CPU 占用；比较 VMCALL 基线。
- 恢复能力：非法指针/页失效/CR3 失效时，HV 应返回 ERR，不应崩溃或卡死。

可选/后续项
-----------
- 多队列：每 VCPU 或每进程一队列，降低跨核争用。
- 认证与加密：握手时加入 key/nonce，或在队列元数据增加轻量校验。
- 定向屏蔽：在空闲时关闭 VMX timer，仅在 R3 触发轻量唤醒（如一次性 CPUID 通知）再开启。

交付物
------
- 代码：CPUID handler、队列管理（HV/R3）、命令处理实现、VMX timer 自适应逻辑。
- 配置/开关：编译时或运行时切换 VMCALL vs 队列通路。
- 文档：握手协议、队列格式、命令列表、错误码、调优参数与测试指引。

