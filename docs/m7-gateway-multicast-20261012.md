# M7：Windows 网关组播通知、共享端口与可让位配额

基线 `66e1b76`。在已完成的单播通知上增加 **IPv4 PCP ANNOUNCE / NAT-PMP 地址组播通知**，接入同一个租约复核流程。已完成本机 Windows 真实 socket、共享端口、取消及正式 UDP 生命周期验证；没有真实路由器或公网 NAT 验收，M7 Gate 仍未通过。

## 实现和边界

- `PortControlMulticast` 每进程、每通知端口只有一个接收者；正式端口固定为 5350，测试使用隔离临时端口。通过同一个全机 `TraversalResources` 账本共享，多 peer / 多网关不各自创建通知 socket。
- 接收者按实际 IPv4 接口加入 `224.0.0.1`，启用 packet information；分发前同时验证目标组播地址、到达接口和已登记网关 IP:port。旧路由代次会在租约侧拒绝通知。此接收者只接受 ANNOUNCE / NAT-PMP 地址消息，不将组播 MAP 当成请求响应。
- Windows 本机实际绑定组播地址失败（地址无效），因此 Windows 使用 ANY + `SO_REUSEADDR`；其他平台使用组播地址绑定，但本轮没有其他平台实测。接口成员关系在最后一个使用者退出时移除。没有扩大到所有网关、创建防火墙规则或发送 LAN 发现请求。
- 接收报文最多 1100B；socket 接收缓冲 64KiB；每 hub 最多 32 个订阅、每秒最多分发 64 个有效提示，不设无限消息队列。对网关的复核请求仍通过既有全机维护包预算。
- 有效提示仍只撤回相应候选并唤醒原租约复核，重启随机等待 0–5 秒、每租约五秒间隔、八秒复核窗口沿用单播实现。来源验证不构成业务身份认证，也不产生新的删除权限。
- 接收器占一个**可回收的可选 socket 配额**。必需数据/打洞/控制资源申请额度时，先取消并等待可选接收循环结束、关闭 socket，然后归还额度。初始化、主动关闭和抢占共用一次性所有权；不增加原来的默认八个上限。
- 若没有额度、接口不可用、共享账本不一致、成员关系失败或端口被独占，则保留单播与普通续租。抢占后不会持续抢回额度；当前账户保持降级，重新建立网关账户时才重新尝试组播，避免反复争抢。
- `PortControlSnapshot` 返回 `NotificationMode` 和 `NotificationReason`；正式 TCP / UDP 候选收集会记录初始模式与原因。后续抢占状态从当前快照读取。业务 Active 的寿命继续独立于映射候选元数据。

默认 `PortControlMapping=false` 不变。只有开启该实验 Provider 并建立网关账户时，才会尝试通知接收器；FakeTCP+HTTP 的线格式、业务数据报和禁止中继约束均未改变。

## 协议与平台依据

[RFC 6887 §14.1.3](https://www.rfc-editor.org/rfc/rfc6887.html#section-14.1.3) 定义 PCP 重启通知的来源、组播目标和恢复等待；[RFC 6886 §3.2.1](https://www.rfc-editor.org/rfc/rfc6886.html#section-3.2.1) 定义 NAT-PMP 地址通知及共享接收端口。Windows 的组播共享例外见 [SO_REUSEADDR 文档](https://learn.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse)，到达接口与目标信息依据 [IP_PKTINFO](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options)。

共享端口测试证明的是组播客户端共存，不能外推为任意单播程序共享 UDP 5350 都无冲突。独占绑定失败时没有强占、关闭其他进程或修改其 socket。

PCP MAP Update 与 MAP 响应仍可能线格式相同，详见 [单播通知记录](m7-gateway-notifications-20261012.md)。本次没有增加事务新鲜度保证；新候选依旧需要远端的真实路径认证。

## 本轮证据

产物在 `artifacts/`，提交及哈希收据为 `m7-gateway-multicast-receipt-20261012.json`。

| 产物 | 结果与口径 |
|---|---|
| `m7-multicast-first-20261012.log` | 首次在原有固定 200ms 取消夹具失败，尚未执行组播用例；保留失败记录，无成功 JSON。夹具改为收到实际创建请求后再取消，明确覆盖“请求已发出但响应不确定” |
| `m7-multicast-second-20261012.json` | Provider 332 + 原 UPnP 10 = **342 检查**；第一组真实回环组播重启复核约 4.144 秒 |
| `m7-multicast-final-20261012.json` | Provider 336 + 原 UPnP 10 = **346 检查**；约 79.68 秒，组播复核约 **3.817 秒**；新增接口/IP 元数据负例、账本隔离和初始化抢占竞态 |
| `m7-multicast-runner-final-20261012.json` | **31 检查**；真实回环 PCP/NAT-PMP/STUN/HTTPS/UDP，正式 factory/Runner/MeshLink，内层 IP 适配器为内存实现 |
| `m7-multicast-traversal-20261012.log` | **82 检查**；原 UDP 同 socket、prflx、MTU 门槛、认证、总账及取消回归，真实回环加明确的 NAT 模型 |

真实组播用例只在 loopback 上发送，TTL=0、隔离临时端口，不向真实 LAN 网关发测试请求。StreamLink 前后各打开一个独立组播 socket，两个都实际收到同一份通知，并核对 Windows 提供的目的组播地址、来源端点及接口号。不同来源端口、单播目的、畸形/超长包和 MAP 通过实际数据报负例验证；不同接口号和来源 IP 的拒绝使用元数据负例，**没有第二张物理网卡验收**。

30 轮并发关闭/抢占是资源竞态检查，不是 30 次真实 NAT 重启。另测了初始化尚未完成时发生抢占，必需资源必须等真实可选资源关闭后才能取得额度。

正式 UDP 测试按顺序创建并映射七个真实数据 socket：第一个可使用组播，第七个回收组播额度，最终为七个数据 + 一个共享控制 socket。既有映射和端口所有权保持；全部退出后八个额度均可再次申请。

获胜路径测试结束 Attempt 引用后，使用组播重启通知使映射进入 `GatewayRevalidating`。原获胜 socket 仍顺序双向承载 1344B 完整载荷；复核后资源身份不变，最后一个路径引用关闭才删除 PCP 映射。它证明生命周期分离，**不能保证真实路由器清空 NAT 后业务必然不中断**。

核心、应用、服务与受影响测试 Release 构建通过，无警告/错误。最新安装包没有重打，现用服务没有替换。

## 尚待完成与回退

剩余 M7 项目包括：入口收集脱离 STUN 成功依赖、真实路由器组播/映射互操作、物理多接口变更、真实 IPv6 / WinDivert / Wintun / PMTU Gate。当前网关 Provider 使用 IPv4，未实现 IPv6 PCP 的 `[ff02::1]:5350` 接收；不要把外层 IPv6 承载能力误写成 IPv6 网关控制能力。

代码回退基线为 `66e1b76`。产品侧可以关闭原 PCP/NAT-PMP 实验选项并重启该网络，回到既有入口路线。没有改动 Lucky、现用 StreamLink、安装服务、网卡和防火墙。
