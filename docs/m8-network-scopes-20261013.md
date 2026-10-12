# 受管 TCP/UDP 出口代次与恢复

此项是 0.5.4 发布后的 0.5.5 开发分支进展，尚未进入已发布的 0.5.4 二进制。保留 FakeTCP＋HTTP、原有 SEQ/ACK、MeshLink 密码会话、业务数据报语义和禁止中继约束。没有修改两台机器的现用服务、网卡、Lucky 或协调服务器配置。

## 实际产品接线

`MeshCandidateFactory` 在正式候选收集、Prepared 和 Activate 流程持有出口代次。C# 同 socket UDP、原生 SO、预测、来源学习、独立备用与概率探索均经过统一代次边界；异步方法不会在等待途中悄悄改用新代次。准备/激活迟到的结果会被回收。

Windows 用只读 `GetBestRoute2` 查询实际源地址、接口 LUID/index 和下一跳，并结合地址前缀、DAD 与接口状态形成快照。快照排除持续变化的 age/lifetime/metric 计数；端口号不改变 IP 路由快照。地址或可用性事件只触发检查，经过 250ms 合并；另有每 5 秒的只读检查兜底。发送首个 SYN 前还会再次核对观察过的实际路由，不依赖事件一定及时到达。

只有已使用目标的出口快照变化才创建新代次。无关 VMware 等接口事件不会直接销毁链路；观测不确定时拒绝新候选，不把未知出口当成可靠资源。跟踪至多 64 个目标 IP，超限明确返回 BudgetExhausted。对当前受管工厂而言，相关变化统一使未完成候选失效；尚未实现多个出口的独立 pacing 和更细的逐出口调度。

`MeshTraversalManager` 在原调度循环中检查变化，取消未完成/备用候选并刷新前台机会窗，保留已选中 actor、精确 socket/capture tuple 和加密会话。旧控制序号历史保留，迟到结果不能绕过取消。`MeshRouter` 同时撤销旧负载诊断与质量批准；旧路径是否继续承载由实际双向健康决定。

旧 TCP 源池退役后禁止新借用，其 Active worker 继续持有原捕获与 helper 引用；新源池仍共享原全机配额和同一个 pacer，没有为切网额外增加出口速率或端口额度。UDP 获胜 socket 保持唯一接收者。反射失效、端点所有权、原生退出与链路健康仍分别处理。

原生准备对象与实际路径可能是同一个 `NativeDatagramPath`。新增封装显式保留这一所有权语义：结束 Attempt/Prepared 不再因对象包了一层就关闭 Router 的 Active。真实路径的资源退出任务用于持有出口引用，直到 I/O 和所属引用收敛；失败关闭不当成退出成功。工厂关闭幂等，先拒绝新尝试，再取消/加入观察、源池、真实路径及剩余引用。

校准/观察结果只有属于当前代次才可更新模型。旧任务的报告保存为含代次的历史文件，不覆盖当前资格报告。新代次撤销已有端口预测，不能跨出口复用训练证据。

Windows API 依据：[路由查询](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getbestroute2)、[结构定义](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_row2)、[地址变化事件](https://learn.microsoft.com/en-us/dotnet/api/system.net.networkinformation.networkchange.networkaddresschanged?view=net-10.0)。这些 API 不构成 NAT 可达性或公网建链证明。

## 验证与失败记录

复现入口：

```powershell
dotnet build tests/StreamLink.MeshRunnerTraversalTests -c Release
dotnet tests/StreamLink.MeshRunnerTraversalTests/bin/Release/net10.0-windows/StreamLink.MeshRunnerTraversalTests.dll --native out/native/udp2raw-protocol-test.exe --rounds 30 --output artifacts/network-scopes.json --network-only
```

Local 验证入口采用 30 轮，未来 Package 在完整回归中采用 1 轮短回归。使用实际 TCP/UDP socket、C++/IPC、HTTPS、Factory/Actor/Router/Runner；raw 和内层 IP 适配器为内存，路由变化通过受控快照注入。只读路由 API 在本机实际执行，不改变系统路由。

最终结果见 `artifacts/m8-network-fixed-20261013.json` 与 `m8-calibration-fixed-20261013.json`。30 轮分别覆盖 TCP/UDP：无关事件、通知合并、同源下一跳变化、事件前首发校验、旧候选/Start、迟到解析、原引用未释放时新资源准备、重复轮询。额外正例覆盖 Attempt/准备退出后的实际双向 1280B IP，以及一次正式双端 Runner 的保留与 worker 退出恢复。

旧源证据过期/工作进程退出的恢复、上述路由变化夹具与物理 NIC 切换是不同证据。正式夹具恢复记录是状态重连后双向完整 IP 成功的本地总等待，不等于计划中的 StableBusinessStart、WAN 延迟或串流质量。原生正例由 C++ 测试后端处理，不能冒充生产 WinDivert 线上 RST 证明。

最终出口用例 619 项检查通过，其中 TCP/UDP 各 30 轮边界验证；一次正式双端恢复的上述总等待为 7,300ms。校准与取消 43 项、修复后正式基线 97 项通过。0.5.5 界面和服务 Release 构建均为零错误、零警告；这不是新安装包或正式安装验证。

首轮用生产 native 对回环 peer 运行时按生产限制拒绝 attach；记录为不适用的运行环境，后续改用既有协议测试后端。UDP 准备首轮的测试上下文没有复用 Gather 的 AttemptId，已修正并保留失败日志。基线又发现工厂重复关闭的取消源问题，已修复幂等关闭后通过。

校准取消回归还发现工厂等待未使用的调用者候选引用，形成循环等待。记录在 `m8-calibration-stall-20261013.json`；仅停止了已核实身份的本地测试进程。关闭等待已改为实际 I/O 和已激活路径，未使用候选仍由调用者释放；操作引用的取得与关闭检查也在同一锁内完成。现用两台 Windows 服务仍 Running，PID 分别为 7108/7444；协调服务仍为原 PID 3676373。

预测回归曾因两秒新鲜度到期而返回 PredictionClaimRejected；没有延长上限。隔离一轮通过，两方向及反射后备的两轮复跑 36 检查通过；这不将首次失败改记为成功，也不证明公网预测成功率。

相关回归：正式基线 97、TCP 来源学习 28、UDP 探索 35、原生备用 29、受管 Router 222、TCP/mesh 连接 71、旧连接生命周期 19 检查通过。完整产物在 `artifacts/m8-*20261013.*`，带有回环/受控边界；新的整包回归、Windows 实际安装和生产切网 Gate 尚未执行。

## 启用范围与余项

本次资源正确性处理随已经许可的受管模式使用，没有新增默认打洞策略。设备默认仍 `TraversalMode=legacy`；SO/UDP/增强能力依旧独立关闭。旧 P→Q 兼容入口本轮没有增加出口事件处理，不能声称默认路径的所有睡眠、IP 更换和切网已经完成。

真实 VMware 桥接、物理断网/网卡重建、Wi-Fi/有线切换、睡眠唤醒、无人登录冷启动、公网端点再验证、三台/八台 Windows 及稳定恢复统计仍需相应环境。这些 Gate 保持未通过；当前实现不能增加任意严格 NAT 必通的承诺。
