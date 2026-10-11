# M1 受管 native 接入阶段记录

本项继续执行总计划；**M1 Gate 尚未全部通过，M0—M9 总目标未完成**。

## 实现

- 原 EndpointPoc 的真实独占 TCP owner 移入 `StreamLink.Core/TcpEndpointLease.cs`，测试引用同一实现。
- 增加 NativeAttachment 独立引用。每个 Lease 同时只能有一个 attachment；查询流失效与源资源释放分开。
- ABI 1 本地管道：固定 96 字节消息、类型、请求序号、Lease/网络代次/AttachId、源/辅助/对等 tuple、角色/profile、描述版本。
- 父端管道限制当前身份并核对实际子 PID；native 核对管道服务者是实际启动父进程。没有 skip-bind 环境开关。
- Armed 后接收 Start 才发送；每次授权独立 AttachId；控制管道关闭/失效终止注入。撤销与注入互斥；父端确认进程退出才释放 attachment。
- 受管模式不第二次 bind P。当前明确限制单 peer；只捕获授权的对等四元组，两向 helper tuple 排除；捕获的内核出站报文不发送，自身从该 WinDivert handle 注入。
- 捕获缓存修复为完整描述比较，先关闭旧范围再打开新范围；受管实例不在原地改变描述。
- 默认 MeshRunner 仍用原入口；多 peer broker、共同提名、SO 尚未接线。不会将本轮原型宣告为正式新能力。

## 本地真实进程与协议证据

初次执行：

- `artifacts/managed-attach-local-20261011.json`：30 轮 / 211 项检查；C# 独占内核辅助流 + 两个真实 native 子进程，raw 报文仅经测试 UDP 回环承载。包括正常撤销与最后一轮 worker 被杀。
- `artifacts/managed-attach-negative-20261011.json`：错误 ABI、旧 AttachId、旧网络代次、错误请求序号、Start 前 IPC 断开五项，native 退出且 Start 前无 raw 发包。
- `artifacts/endpoint-lease-core-20261011.json`：移入 Core 后的原 30 轮 / 244 检查通过。
- `artifacts/protocol-managed-20261011.json`：10 个既有 C++ 协议回归通过，HTTP/bare 重叠序号保持。
- 统一入口 `scripts/Invoke-TraversalValidation.ps1 -Profile Local` 重建两种 native binary 并生成源提交/dirty/OS/hash/日志 manifest。

这些证据不能替代 WinDivert、NAT 和正式产品路径。

## 两台真实 Windows 的初步 I/O

Thinkbook 和 Akane，使用已有 10.129.129.2/1 虚拟网络接口连接两个独立 Windows 协议栈。测试进程位于 Akane 的 `E:\Codex_Workspace\Streamlink\m1-coexistence-20261011-a`；没有替换现用服务。新增入站规则仅限指定对端、测试 IP 和 TCP 端口，结束时删除。

这是**真实 Windows/WinDivert 经现有虚拟网络接口的测试**，不是原生物理 LAN、独立公网 bootstrap 或 NAT 穿透证据；底层旧网络提供该试验的可达性。

第一轮（43161/43162，helper 43163/43164）：

- 本机收到 117 个 1200B echo；两端辅助查询 127/134 次。
- 两端入站 SNIFF 观察范围内 RST 为 0。
- 本机先结束，远端 helper 随后 EOF，使早期 harness 将查询失败计为整轮失败。该结果保留，不能写成双方通过：`artifacts/m1-two-windows-{local,remote}.json`。
- 更早的后台 SSH 启动尝试因 SSH 子作业退出导致远端未持久运行，helper 连接超时；改为保持 SSH 命令会话直至测试完成。未将该失败计入协议通过。

第二轮（43171/43172，helper 43173/43174），主动在约 12 秒后停止反射回复：

| 结果 | Thinkbook | Akane |
|---|---:|---:|
| 业务收到 | 120 | 120 |
| 超时前成功 helper 查询 | 53 | 43 |
| 本端 helper 查询失效后收到业务 | 73 | 74 |
| 接收侧观察 RST | 0 | 0 |
| 观察器报告错误 | 0 | 0 |

两端测试进程正常退出。helper 超时后保留真实源资源，native 继续承担业务，没有为恢复查询而关闭重绑。数据/握手总数不是吞吐、QoS 或零丢包基准；初始握手期间 client 有尚未得到 echo 的探测。

产物：`artifacts/m1-two-windows-local-b.json`、`artifacts/m1-two-windows-remote-b.json`。每项保存 LeaseId、AttachId、真实源/目的端点、辅助反射值和包头元数据。

观察点是**远端 Windows NETWORK 入站、优先级 200 的 SNIFF**，早于受管 priority 100 截获；不保存业务 payload。不是物理 tap，没有外部 NIC/offload 丢包审计，不能声称所有物理线上 RST 已被独立排除。查询失效和 raw 会话成功是独立记录。

## 仍须完成

1. M1 的受控双 Windows 30 轮、跨进程争抢/父崩溃、真正公网端点连续性与完整观察证据。
2. 原生共享端点的多 peer 授权分流（当前仅单 peer），正式 MeshRunner 接入和统一预算。
3. M2 双主动、M3 共同提名及其余 M4—M9。Local 通过不解除真实发布 Gate。

当前测试私密配置只位于 ignored 的 out/及远端测试目录；日志脱敏；不将密钥或配对信息加入仓库。
