# Hypervisor 改造方案

## 1. 静态特征去除 (Static Signature Removal)

### 1.1 内存池标签 (Pool Tag)
*   **现状**: 代码中使用硬编码的 `'fr0g'` 标签。
    ```cpp
    ExAllocatePoolWithTag(NonPagedPoolNx, arr_size, 'fr0g');
    ```
*   **风险**: 极易通过 `PoolMon`、系统 BigPool 表扫描或内存特征匹配发现。
*   **改造方案**:
    1.  **随机化**: 每次驱动加载时生成一个随机的 4 字节 Tag（最好是不可打印字符或看起来像正常的系统 Tag）。
    2.  **伪装**: 使用常见的 Windows 内核 Tag，如 `None` (0), `Ddk `, `Se  `，混入系统正常的内存分配中。

### 1.2 字符串与日志特征
*   **现状**: 大量 `HV_LOG_*` 宏展开为 `DbgPrint`，包含 `[sq]`, `[hv]` 等明文前缀。
*   **风险**: 简单的字符串扫描即可定位驱动文件或内存中的驱动模块。
*   **改造方案**:
    1.  **Release 构建清理**: 确保在 Release 配置下，所有日志宏定义为空，不编译进任何字符串。
    2.  **编译时加密**: 如果必须保留调试信息，使用 `xorstr` 等技术在编译期加密字符串，运行时解密，避免静态明文。

### 1.3 移除 VMCALL 接口
*   **现状**: `hv/exit-handlers.cpp` 中 `emulate_vmcall` 仍包含处理逻辑，且使用静态 Key `69420`。
*   **风险**: AC 可主动执行带有该 Key 的 `VMCALL` 指令进行“撞库”探测。
*   **改造方案**:
    1.  **彻底删除**: 删除 `emulate_vmcall` 函数及其所有引用。
    2.  **模拟异常**: 在 VM Exit 处理逻辑中，若 Exit Reason 为 `VMCALL`，直接向 Guest 注入 `#UD` (Invalid Opcode) 异常。
    *   *目的*: 让 Guest 认为当前 CPU 根本不支持 VMCALL 指令，或者不在虚拟化环境中。

## 2. 通信隐蔽化 (Stealth Communication)

### 2.1 改造 CPUID 握手
*   **现状**: 拦截非标准 Leaf `0x1337` (`shared_queue_cpuid_leaf`)。
*   **风险**: 异常的 CPUID Leaf 是极强的检测特征。任何扫描 `CPUID(0x1337)` 返回非空值的行为都会判定为作弊。
*   **改造方案**:
    *   **放弃 0x1337**。 
    *  **策略: 劫持标准 Leaf**
        *   拦截 `CPUID(0x80000000)`。
        *   检查输入寄存器（如 `RBX`, `RCX`, `RDX`, `RSI`）是否匹配特定的 **Magic Value**（高熵随机数）。
        *   **只有**当 Magic 匹配时，才执行握手逻辑；否则透传给物理 CPU，表现得像一个正常的 Windows 环境。

### 2.2 共享队列 (Shared Queue) 加固
*   **现状**: 队列结构体和指令数据以明文存储在共享内存中。
*   **风险**: 启发式内存扫描（Heuristic Scanning）可能识别出“生产者-消费者”队列的特征结构。
*   **改造方案**:
    1.  **轻量加密**: 在队列初始化时协商一个会话密钥 (Session Key)。所有写入队列的数据（Cmd, Addr, Size）都进行异或 (XOR) 或流加密。
    2.  **结构混淆**: 避免在 Page 的起始位置放置 `head`/`tail` 指针。在注册队列时，随机指定一个偏移量 (Offset)，将队列结构隐藏在页面的中间位置。

## 3. 内存隐蔽与反自省 (Memory Stealth)

### 3.1 物理内存自隐藏 (Self-Hiding)
*   **现状**: EPT 使用恒等映射 (Identity Mapping)，Guest 可读写所有物理内存，包括 HV 自身。
*   **风险**: 简单的物理内存遍历即可 Dump 出 Hypervisor 代码。
*   **改造方案**:
    1.  **EPT 重定向**: 识别存放 Hypervisor 代码和数据的物理页帧 (HPA_HV)。
    2.  **诱饵页**: 申请一块相同大小的空闲物理页，填充随机数据或全零 (HPA_DUMMY)。
    3.  **修改 EPT**: 在 EPT 中，将 Guest 对 HPA_HV 的访问映射到 HPA_DUMMY。
    *   *效果*: Guest 读取 HV 内存地址时，读到的是无意义数据；Guest 写入时，写入的是诱饵页，不影响 HV 运行。

### 3.2 驱动对象擦除 (DKOM)
*   **现状**: 驱动作为标准内核模块加载，在 `PsLoadedModuleList` 和 `DriverObject` 链表中可见。
*   **风险**: 枚举驱动列表直接暴露。
*   **改造方案**:
    *   在 Hypervisor 初始化完成并接管系统后（`virtualize_cpu` 成功）：
        1.  从 `PsLoadedModuleList` 双向链表中摘除该驱动节点。
        2.  清除 PE 头 (MZ/PE Header) 以防止基于内存签名的扫描。
        3.  注意：需处理 PatchGuard (KPP) 风险，但如果是 Hypervisor 层面拦截读取，可以直接欺骗 KPP。

## 4. 反检测与反时序 (Anti-Detection)

### 4.1 修正 CPUID(1) 特征
*   **现状**: 透传 `CPUID(1)`。
*   **风险**: `ECX` 寄存器第 31 位 (Hypervisor Present) 为 1。
*   **改造方案**:
    *   拦截 `CPUID(1)`。
    *   `AND ECX, 0x7FFFFFFF` (清除 Hypervisor Present 位)。
    *   让系统看起来是在裸机上运行。

### 4.2 RDTSC 时序修正
*   **现状**: `RDTSC` 可能触发 VM Exit 或直接透传，VM Exit 开销导致时间差异。
*   **风险**: 时序攻击 (Timing Attack) 可轻易检测虚拟化延迟。
*   **改造方案**:
    *   在 VM Exit 处理程序中，记录处理该 Exit 消耗的 TSC 差值。
    *   在返回 Guest 之前，调整 `TSC Offset` 或修改 Guest 寄存器中的 TSC 返回值，减去这部分开销。
    *   *目标*: 让 `RDTSC` 测得的两条指令间隔时间接近裸机水平。

## 5. 实施路线图 (Roadmap)

1.  **Phase 1: 基础清理**
    *   随机化 Pool Tag。
    *   移除 `hv/exit-handlers.cpp` 中的 `emulate_vmcall`。
    *   定义 `HV_NO_LOG` 并在 Release 模式下禁用日志。

2.  **Phase 2: 通信重构**
    *   实现基于 Magic Value 校验的 `CPUID(0x80000000)` 握手。
    *   移除 `0x1337` Leaf。

3.  **Phase 3: 核心隐蔽**
    *   实现 EPT 自隐藏逻辑 (Remap HV pages to Dummy)。
    *   拦截并修正 `CPUID(1)`。

4.  **Phase 4: 进阶防御**
    *   驱动断链 (Unlink Driver)。
    *   RDTSC 时序平滑处理。

