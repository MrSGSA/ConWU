# StreamLink RC2 源码修复交付（基于 f5535e44）

交付性质：**已修改源码＋补丁＋新增回归用例＋本地 C/C++ 实测，不是已构建或验收通过的 Windows RC2 安装包。**

原始输入：`StreamLink-1.0.0-rc1-PRO-handoff.zip`。源快照标识 `f5535e44a26ee965acc87c31bca8b0e4e70fb63a`，交接注明的代码候选 `1e7928e4868e93919417330eede62d9896de8d99`。本次未连接、修改或部署用户的真实仓库/服务器/0.3.2 服务。

## 1. 本次实际完成的修改

### RC2-01：UI 原子补丁、幂等、编辑草稿

修改 `ControlWorker.Ui.cs`、`ControlWorker.cs`、`ControlWorker.Operations.cs`、`UiControlProtocol.cs`、`UserWindow.cs`；新增 `UiSettingsDraft.cs`。

- 日常 UI 只递交原始 `UiConfigPatch`，不在排队前复制整个 `DeviceProfile`。
- 新增私有 `ui-patch` 操作，在现有 `requests` 串行入口与 `sync` 锁内，从最新配置应用白名单字段。网络设置、目录及新 STUN 观察不会被旧 UI 快照覆盖。
- 出队后再次核实调用者授权。没有经认证的 UI 上下文，不能通过管理员通用命令伪造这个内部操作。
- 操作摘要绑定原始请求、补丁及调用者；相同操作 ID 的重复请求不再因无关配置变动变成另一个请求。失败操作的重复结果继续是失败，而非 Ok。
- 名称/日志补丁只热更新相关字段，不执行 End/Begin，不为一次改名重建网络。
- `SettingsPatchVersion=2` 增加按被编辑字段的原值前置条件。无关字段变化不冲突；同一字段被别人改了则拒绝静默覆盖。不是新建整套配置版本协议。
- 与旧 v1 后台交互时不发送它不认识的 expected 字段；旧客户端仍可提交原有白名单补丁，但没有新增的同字段冲突保护。
- 编辑草稿与后台状态分离，轮询不覆盖 dirty 字段。新增明确撤销、冲突提示及本机虚拟 IP 复制；过期的轮询回复不会覆盖保存后的状态。
- 传输失败时，同一未改变的补丁保留操作 ID，避免不确定是否提交成功时重复执行。

控制测试同时隔离配置目录和具名管道；链接普通用户子进程继承同一随机 validation ID，不占用生产 UI/管理管道。

新增 `UiPatchTests.cs` 固定“管理员持锁保存→UI 排队→管理员提交→UI 补丁”的顺序；覆盖新网络设置不回滚、失败结果重放、ID 冲突、健康 worker 不被停止、排队期间撤销授权。

新增 `StreamLink.Rc2PortableTests` 检查草稿跨多轮轮询、字段冲突、撤销、旧协议序列化及授权选择策略。**本容器没有 .NET，这两类托管测试尚未编译和运行。**

### RC2-02：安装授权不再等同于提升进程身份

新增 `UiAuthorizationPolicy.cs`、`UiUserSelection.cs`；修改 `ServiceInstaller.cs`、`ProfileStore.cs`、调用入口及打包/隔离安装脚本。

- 升级默认保留原合法 UI SID，管理员 B/C 执行升级不会自动夺走日常用户 A 的授权。
- 首次安装必须明确选定日常登录账号。交互安装提供空白账号输入、Windows 账号解析、账号与 SID 的再次确认；不自动填入当前提升账号。
- 命令行自动化支持 `--install --ui-user-account 域\用户名`，仅提升管理员可执行，账号先经 Windows 解析并要求是用户而非组；不接受任意 SID 字符串。
- `--install-ui` 用于交互安装。安装包的 `Install-Service.ps1` 已改用此入口。
- UI 选择发生在前台释放/服务停止之前，取消选择不会先断开当前网络。
- 受保护配置目录中的独占安装锁串行化安装事务；授权文件使用随机临时文件和原子替换，授权创建及回滚写入受保护审计日志。
- 安装不承担隐式重授权：现有授权与指定账号不同会明确拒绝。历史上已经错误授予其他用户的配置，不能靠一次升级自动判断其真正所有者；单独的“更换日常用户”管理流程不在本次实现范围。
- 保留授权恢复和服务回退两个独立失败分支；回滚不会覆盖另一个管理操作刚写入的新授权。

真实 A 标准用户、B/C 管理员的跨账户 UAC、管道拒绝、安装与升级仍需 Windows 实测。现有同账户隔离安装脚本被明确标注，不能充当上述证据。

### RC2-03：Wintun 关闭诊断与可终止的生命周期夹具

**尚未声称修复官方 Wintun 的历史关闭失败根因。** 本次补的是定位工具和可靠的失败收集。

- `transport/tun/adapter.cpp` 新增可选 `sltun_close_with_trace` 导出；原 `sltun_close` 与 ABI 2 保持，默认关闭顺序不变。
- `NativeAdapter` 可选记录 stop、独占锁等待、native close、Wintun session end、adapter close、Wintun DLL 释放和桥接 DLL 释放阶段。旧 DLL 缺该导出时记录诊断不可用，不伪造阶段。
- 回调同步且保持引用，诊断记录异常不会抛过 native 边界。此回调仅用于受控诊断；其开销不能当成正式性能数据。
- 每轮官方适配器生命周期试验在独立子进程中运行，父进程具有 30 秒兜底 watchdog，只处置本次自行创建的子进程树，不删除他人网卡或共享驱动。
- **原 3 秒 I/O+关闭判定与关闭后立即枚举自有接口的断言保留。** 30 秒是超时收束，不是放宽通过标准。
- 若 PnP 稍后才消失，记录最多 5 秒的后续可见性变化，但原立即消失断言仍记 Fail。
- 失败清理不再在 finally 中无界同步 Dispose；先落盘阶段、线程状态及结果。没有实际采集 native 调用栈或转储，不把线程状态当成栈。
- 读、写、统计和关闭使用专用测试线程，排除线程池排队造成的部分夹具歧义；生产代码没有因此替换线程架构。
- `--lifecycle-watchdog-selftest` 只挂起一个自有子进程验证监督器，不加载网卡或驱动。

**特别限制：逐轮进程隔离能定位卡死，不能证明“同一长寿进程 100 轮无累计泄漏”。** 报告显式输出 `sameProcessLeakGatePassed=false`。定位根因后，还需原有同进程和已安装服务的长周期 Gate，不允许用 100 个新进程冒充。

### RC2-07：研究 TUN 的预取消计数与取消回调锁序

修改 `drivers/StreamLink.Tun/driver.c`，新增实际共用的 `read_reservation.h`。

- 每个 READ 使用 `DriverContext[0]` 保存独立配额 reservation，避开 CSQ 保留的 `[3]`。
- 出队和取消完成均调用同一原子、幂等 release。插入前已取消也归还 reservation；已入队后取消不会双减。
- `PendingReads` 明确表示含插入前短窗口的 reservation；新增内部 `QueuedReads` 只在真正 CSQ 插入/移除时变化。
- Drain 的再调度基于实际 `QueuedReads`，不因尚未插入或预取消的 reservation 反复调度空队列。
- `ResearchTunAdapter.Read` 的取消注册建立和释放移到 lifetime 读锁之外，避免读线程持读锁等待取消回调、取消回调又排在关闭写锁之后的环路。
- 新增程序集内部测试委托入口和专用友元测试程序集，调用实际 Read/Stop/Dispose 方法但不加载 DLL/SYS。公开研究构造器的管理员和显式批准要求没有放宽。
- 自研 WFP 仍是观察样机，未补注入实现；默认仍是官方 Wintun/WinDivert，不生成、签名或加载新 SYS。

新增 C++ 测试直接 include 生产 reservation helper；新增 `Rc2ResearchTests` 用三个线程固定 read、write-waiter、cancel 的时序。前者已执行，后者等待 Windows/.NET 编译运行。**宿主 helper 成功不等于 Windows CSQ/IRQL/Driver Verifier 通过。**

### RC2-04/08：来源、回归与交付

- 新增 `Test-Rc2SourceFix.ps1`：Windows 构建、UI/控制/研究锁序/适配契约测试、watchdog 自测；默认不安装服务、不加载驱动。`-RunFullCore` 才调用原完整核心回归，不能用 tail 子集替代。
- 所有步骤有独立日志、有限执行窗口、首个失败保留，测试前后核对源文件实际字节。核对结束字节相同不能侦测“中途修改后又改回”，执行时仍应使用冻结分支/工作副本。
- `-AllowIsolatedAdapterTest -Components <固定重建产物>` 是显式硬件动作许可，不由默认验证偷偷开启。路径/哈希会记录，但仍需另核对它确实对应本源码构建。
- 新增 Linux 检查脚本，保存实际命令、输出、编译器和输入/二进制哈希。
- 修正旧 `REL-02` 中“没有构建安装”的过时文字：历史 RC1 隔离安装/回退有 Pass，但范围是同 RC、业务关闭；本次源码修改没有被构建安装。
- 保留全部历史 Fail，不以本地 Pass 解释旧兼容认证超时。

## 2. 本次真正执行的验证

最终固定的 C/C++ 测试输入由 `evidence/final-linux/inputs-before.json` 与 `inputs-after.json` 核对相同。

| 检查 | 本次结果 | 不能替代 |
|---|---|---|
| 完整生产 TCP 解析器，g++ ASan/UBSan | 29,659 项，含 20,000 次变异；0 失败 | Windows raw/broker/offload、所有攻击输入 |
| 现有 C++ SO 状态模型，g++ ASan/UBSan | 630 项通过 | 真 Windows 双主动、公网 NAT 和业务覆盖 |
| 生产 reservation helper，g++ ASan/UBSan＋线程竞争 | 935 项通过；最终运行 23,000 次成功准入，余者可因配额合法拒绝 | 完整驱动、IRQL、真实取消安全队列、PnP/电源 |
| 项目 XML、引用存在、git diff --check | 通过 | Roslyn/MSBuild/PowerShell 语法或编译正确性 |
| 原 transport/udp2raw 全部 99 个跟踪文件 | 内容未改（只按 Git 文本行尾归一化比较） | 其他模块/运行时行为没有回归 |

准备阶段有一次 SO 编译漏传 `-Itransport/udp2raw`，返回“native_so_state.h not found”；修正调用命令后通过。它属于本次命令准备错误，不是修改产品才能消除的故障。早期与最终 helper 的准入数不同属于并发调度差异，原始日志分别保留，不拼接成一个结果。

环境是 Linux，`dotnet`、`pwsh`、Windows/WDK 不可用。因此 **C#、WinForms、服务、PowerShell 脚本、Windows C++ 桥接、自研 SYS 都没有在本环境完成编译或实测**。新增托管回归是已写入而非已通过。没有安装包，也没有正式发布批准。

## 3. 八项整改的状态

| RC2 项 | 本次状态 | 仍需完成 |
|---|---|---|
| 01 UI 原子补丁/幂等/草稿 | 代码与回归用例已交付；托管未验证 | Windows 构建、受控并发和桌面交互 |
| 02 安装授权 | 代码与策略测试已交付；跨账号未验证 | 标准用户 A＋管理员 B/C、UAC 取消、实际升级回退 |
| 03 官方生命周期 | 定位/隔离工具已交付，根因未关闭 | 复现历史失败、根因修复、同进程/服务长期 Gate |
| 04 固定完整回归 | 实测 C/C++ 子集通过；未完成 | Windows 完整核心、旧兼容认证超时定界 |
| 05 FakeTCP 新增覆盖 | BlockedExternal | 两台真实 Windows、确认拓扑、同版本 off/on、真实业务 |
| 06 质量/业务升级 | BlockedExternal | 固定新包双方向 50Mbps、实际 60 分钟、业务升级及八设备等 |
| 07 研究驱动 | 代码＋helper 实测；其余未验证 | 托管锁序测试、WDK、恢复型内核实验机及签名/安全 Gate |
| 08 交付矩阵 | 源码修复包已交付；不是正式 RC2 | Windows 编译产物、上述 Gate、默认能力决策 |

## 4. 接入方式

使用新分支和干净工作区。完整源码 ZIP 适合独立核验；真实开发仓库建议使用补丁，先 `git apply --check`。本补丁基于 f5535e44 快照，不覆盖之后的修改。

```powershell
# 在实际仓库执行；先处理自己的未提交改动，不运行 reset --hard。
git status --short
git switch -c fix/rc2-sourcefix
# 将下面路径改为本次交接包中的补丁路径。
git apply --check "D:\Handoff\StreamLink-RC2-SourceFix-f5535e4.patch"
git apply "D:\Handoff\StreamLink-RC2-SourceFix-f5535e4.patch"
```

若上下文不匹配，按文件作三方审查/人工合并；不要用忽略所有差异或覆盖整个仓库来“成功应用”。本次提供完整源 ZIP 与逐文件哈希供比较。补丁的可重放检查使用 Git 的规范化文本内容；完整源 ZIP 保留实际工作副本字节，未修改文本可能保持原 CRLF。

先在具备 .NET 10、PowerShell 7 的 Windows 开发测试机运行以下命令。控制边界测试需要其原有管理员/链接普通用户测试条件；不满足时应保留失败或阻塞原因。

```powershell
pwsh -NoProfile -File .\scripts\Test-Rc2SourceFix.ps1
# 完整核心测试另需原工程 native 编译/Python 等开发依赖；不安装产品。
pwsh -NoProfile -File .\scripts\Test-Rc2SourceFix.ps1 -RunFullCore
```

准备受控虚拟网卡试验时，先按原 `Build.ps1` 重建桥接 DLL并核对精确组件；确认测试不承担当前远程访问，再显式开启隔离试验：

```powershell
pwsh -NoProfile -File .\scripts\Test-Rc2SourceFix.ps1 -AllowIsolatedAdapterTest -Components "D:\FixedComponents" -AdapterRounds 100
```

这不是授权替换生产服务，不是加载研究 SYS。详细外部步骤见同目录 `windows-checklist.md`。

## 5. 不变的范围与剩余决策

- 未修改 TCP/FakeTCP SYN/HTTP/SEQ 数据 profile、NAT 算法、pacing 策略、默认实验开关或内层密码协议；网络收益不在本次主张范围内。
- 无业务中继，无新增可靠外层业务重传，无自动扩大端口扫描。
- 没有替换现用服务、协调服务器、官方驱动或签名状态。
- 项目默认版本仍保留输入的 rc1，避免把未构建源码伪装成正式 RC2；后续发布打包时再统一版本。
- 原官方关闭失败、兼容认证超时、真实 SO 增益、当前包质量与最终发布 Gate 继续未通过/未验证。

交付后的 Codex 工作应是 **审查/合并这份具体补丁 → Windows 编译并处理编译或回归失败 → 用新定位工具调查历史问题 → 真实网络与安装验证**，而不是重新执行前一轮全部开放式研发计划。

## 6. API 依据与来源边界

代码缺陷来自用户 RC1 源码及前一轮 review；公开资料只用于确定系统 API 契约：

- Microsoft `IoCsqInsertIrp`：预取消 IRP 不插入，DriverContext[3] 为 CSQ 保留。https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocsqinsertirp
- Microsoft `CancellationTokenRegistration.Dispose`：注销需等并发回调结束。https://learn.microsoft.com/en-us/dotnet/api/system.threading.cancellationtokenregistration.dispose
- Microsoft UAC：标准用户提供另一管理员凭据提权与同账号同意提升不同。https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works

这些资料不代替本项目的 Windows/内核/真实网络验收。
