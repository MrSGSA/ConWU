# M3/M4：受管 Router 与 UDP 同 socket 适配

本次把共同提名接入实际 `MeshRouter`，并将 `UdpTraversal` 获胜资源接成该 Router 的数据报承载。仍未完成公网候选 Offer/Ready/Start 的正式 Runner 协商、新 FakeTCP 多 peer 捕获 owner、真实双机 Wintun/PMTU 验收，不能据此标记 M3/M4 Gate 通过。

## 实际接线

- `IMeshDatagramPath` 表达保留的路径资源引用，提供实际资源/端点身份、唯一 Receive、非阻塞且有界的发送接口和异步释放。
- Router 以 PathId/LeaseId（UDP 使用 SocketResourceId）管理候选、Active 和退役引用；候选的 MeshLink 验证附着实际 Receive 来源。
- 每成员保留原有唯一 MeshLink；新旧承载共用方向密钥、发送计数器和重放窗口。
- 注册校验成员、BootId、Attempt、profile、协商控制版本及单调提名 revision；负例不接管调用者的引用。
- 同一实际 TCP 四元组不能同时注册第二个握手状态。不同逻辑 ID 不会绕过检查；该约束不等同于已经实现 native 多 peer broker。
- 候选缺少 Confirm 时旧 Active 继续承担业务；收到有效 Confirm 后提交，确认对端采用后才启动旧路径 2 秒接收宽限。
- 旧资源保留到本轮截止加 2 秒，支持提交/取消期间的回退；这与业务接收宽限分别计时。
- 取消、撤销和退出先停止接收泵，再异步释放本路径引用。旧消息不能恢复已取消路径，也没有成员转发分支。
- 默认 PreferFakeTcp：拒绝用新 UDP 候选替换健康 FakeTCP。UDP 直连状态注明质量待验证，不把连通当成串流质量合格。
- 未受管的旧 loopback 路径不能直接混入新引用系统；旧路径必须先由正式适配器接管。现用默认 Runner 仍走原有承载，避免旧 manager 提前关闭新 Active 依赖。

## UDP 资源与 PMTU

- `UdpTraversal` 继续唯一调用底层 ReceiveFrom，分流 STUN、检查和 MeshLink 载荷。适配器只消费它的载荷通道，不另建或重绑 socket。
- Observe/Punch/在途读取持有独立资源引用；RetainPath 获得长期路径引用。结束原 Attempt/owner 后，路径引用仍持有同一 socket 和全机配额。
- 正式 `UdpTraversal.Create` 工厂先获得资源额度，再绑定 socket；额度不足不额外打开候选端口，绑定失败归还额度。接收已创建 socket 的构造器保留给显式资源适配和测试。
- 只允许一个 payload receiver；拒绝第二个 Path 或旧 API 抢读。路径发送队列最多 128 个数据报，不作业务重传。
- 短时发送缓冲压力/瞬态 ICMP 丢弃当前数据报，不把整个路径误判为永久损坏。
- 新实验检查协议标记为 SLP2，派生域为 udp-check-v2：96 字节小检查验证连通性，1344 字节请求/响应验证所需载荷长度。
- 1344 = 1280 字节内层 IPv4 + 48 字节 MeshLink 头 + 16 字节标签；外层 IPv4+UDP 为 1372 字节。取消把 1400 字节余量当成准入门槛。
- 真实 IPv4 socket 设置并读取 DontFragment；未声明无分片能力的资源不能晋升正式适配器。小检查通过而大检查失败，区分 mtu-unverified；内核 MessageSize 区分 mtu-too-small。
- SLP2 与旧实验 SLP1 不混用，旧实验 UDP 模块没有既有正式部署兼容承诺。后续候选能力公告必须明确声明版本。

**设置 DF 和回环通过，不等于已抓包证明公网未分片。** 本轮结果明确 `wireDfCaptured=false`；真实 PMTU、IPv6 外层、Windows 双机 Wintun 仍需后续证据。

## 控制预算

`TraversalControlRound` 在 UDP 检查与 Router 提名之间共享；晋升 Path 不重置 120 包/64KiB 上限，搜索保留 24 包给完成阶段。诊断用小预算按比例缩减保留量。

受管 C# 控制发送共用原全机 bucket，加入载荷字节、48pps 搜索和 24pps 维护子限额，总上限仍 60pps、8 包突发；心跳/应答不另开维护旁路。Router 定时轮转成员顺序，减少固定顺序抢占。资源引用存活期间继续占 UDP 配额。

目前统计的是上层已准入控制数据报，**尚未把 native SYN、内核 ACK、既有 native heartbeat 及所有外层开销统一纳账**。Ready 前的全机轻/重型排队、TCP 资源池、QoS 业务 pacing、公平队列和维护保障仍属于后续 M3/M6 工作。

## 已执行证据

- `artifacts/managed-router-budget-20261011.json`：31 项实际 Router 检查，使用保留引用的真实回环 UDP 测试适配器；覆盖丢 Confirm、路径回退、同密文消重、退役引用、同 tuple 拒绝、策略保护、成员撤销和退出。
- 该测试的 FakeTCP profile 只用于策略和 tuple 约束，底层为测试 UDP socket，**不代表运行了 native FakeTCP**。
- `artifacts/udp-managed-20261011b.json`：三类各 30 轮。30 对真实 Windows 回环 UDP socket；30 对 EIM/APDF 行为模型；30 对依赖实际来源学习的 EIM/ADF ↔ APDM/APDF 行为模型。全部使用实际 Router/MeshLink 和内存包适配器，双向传送 1280 字节合法 IPv4 包。
- 另检验资源晋升前后同一 SocketResourceId、原配额和控制预算持续存在、第二接收者被拒绝、真实 UDP 候选取消后回退原 socket。
- `artifacts/udp-managed-pressure-20261011.json`：三组各 1 轮补测，加入一次实际适配器发送异常注入；确认瞬态缓冲压力不销毁路径。
- 旧 Mesh 40 项和连接 44 项回归通过。统一入口新增上述受管 Router、UDP 基线和 90 轮适配检查，共 13 步。
- `artifacts/validation-m3b-m4a-20261011/manifest.json`：13 步通过，基于 `ba78a00` 的开发工作树。该批次 UDP 适配共 90 轮、673 项逐步检查；数字不是独立拓扑数。
- 工厂准入顺序后补两项检查：`artifacts/udp-factory-20261011.txt`，UDP 基线合计 82 项通过。先在满额度下尝试占用端口，确认额度拒绝先于 bind；再在有额度时触发 bind 失败，确认额度归还。

NAT 行为模型由测试程序分发数据报，不是实际 NAT 抓包；内存包适配器不是 Wintun。测试不安装驱动、不修改现用服务、路由器或 Lucky 设置。

## 后续接线要求

1. 正式能力公告及 Offer/Ready/Start、候选取消/重启消息，不能仅由测试预先提供上下文。
2. native FakeTCP 与 legacy P→Q 入口适配成受管资源，完成统一源端点捕获 owner 和真实 tuple 回报。
3. 正式 Runner 使用 UDP 工厂、获胜引用和剩余共同期限，完成自动协商接线。
4. 新旧路径切换与质量证据、迟滞/冷却、队列及恢复指标合并。
5. 真实 Windows Wintun、公网 PMTU、受控 NAT 与八设备 Gate，随后打包/升级/回滚验收。
