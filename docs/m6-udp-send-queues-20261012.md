# M6：UDP 发送队列与本地结果账本

基于 `f1614b7` 继续执行计划 §9.2、§9.4。正式 UDP 路径的重复排队和隐式拒绝问题已修复，诊断接入路径、成员和 Runner 状态。**pacing 默认仍为 0，FakeTCP＋HTTP、优先策略及无业务重传行为不变。** 本地发送结果不是公网接收证明，完整质量与发布 Gate 尚未通过。

## 问题和实现

原 `UdpPath` 总是先进入 128 包队列，再交给 `PacedTraversalSocket` 的共享出口队列。出口限额不能涵盖前置积压；pacing 拒绝业务入队时，`Send` 还返回成功。

现在 paced 正式路径直接使用原源的共享出口队列，没有第二个 128 包发送者，`TrySend` 立即返回实际入队结果。STUN、检查与 PMTU 仍用保留完成通知的接口传播真实 socket 错误。接收者、端口、DF、SocketResourceId 不变，已接受入队不被当成对端收到。

未开启 pacing 的 UDP 路径保留异步发送，排队与在途合计最多 128 个数据报、`128 × 1344 = 172032B`。满队列先拒绝再复制。瞬时 socket 压力只丢当前数据报，不重传，也不单独销毁健康路径；明确致命的 paced socket 错误传播到路径 Failed。通用 IP 包没有被赋予视频截止时间。

`DatagramSendSnapshot` 分别记录提交、接受、容量拒绝、不可用拒绝、被其他 peer 挤出、取消、发送失败、发送完成、排队和在途的包数/字节数。同一队列锁下转换和取样，满足：

```text
Offered = Accepted + CapacityRejected + UnavailableRejected
Accepted = Sent + Evicted + Cancelled + Failed + Queued + InFlight
```

Sent 指底层发送回调成功，不是网卡抓包或对端接收。共享 egress 计完整外层 IP 字节，普通 UDP Path 计 MeshLink 数据报字节，状态明确 ByteUnit。每流和出口有各自账本；退役 peer 记录回收不清零出口累计值。增加当前最老排队年龄，既有累计 P95 不冒充当前窗口。

`MeshPathStatus`、成员状态和 IPC 接入 UDP 队列；Runner 已有的 30 秒 pacing 日志增加当前年龄、在途字节、拒绝和账本一致性。native broker 使用相同 egress 账本，但不涵盖前置 IPC、内核 helper、兼容进程或 HTTPS，**不是完整系统线上审计**。

## 实际验证

| `artifacts/` 产物 | 结果与边界 |
|---|---|
| `m6-udp-send-queues-first-20261012.json/.log` | 首次 Fail：在途 I/O 内取消被误计成发送失败。保留失败；按明确取消错误和实际取消状态修复，未放宽断言。 |
| `m6-udp-send-queues-cancel-fix-20261012.json/.log` | 53 检查；真实 Windows UDP/计时器及故意阻塞的发送夹具，覆盖 pacing 开/关、压力释放与取消。 |
| `m6-udp-send-queues-sustained-20261012.json/.log` | 61 检查，通过原 98% 本地吞吐门槛；单成员/七合成成员各 20 秒，约 **49.912 / 49.903 Mbps 外层 IP**。持续排队回调发送模型，不是网卡/WAN 吞吐。 |
| `m6-udp-send-queues-runner-final-20261012.json/.log` | 129 检查，正式工厂/Runner/HTTPS/helper/C++、IPv4/IPv6、旧能力回退、完整双向内层业务及最终账本。UDP 真实回环；native raw/IP 为内存，未用 WinDivert/Wintun。 |
| `m6-udp-send-queues-udp-managed-20261012.json/.log` | 673 检查，同 socket Router/PMTU/prflx/所有权；真实 Windows UDP 回环 30 轮、两个模型各 30 轮。 |

阻塞源用例中，1Mbps paced 路径只接受两个完整业务数据报（一个在途、一个排队），其余立即拒绝；普通 UDP 接受 128 个，总 pending 字节未超限。取消后全部已接受包归入取消，没有漏记或额外发送。压力释放时第一包故意返回瞬时 socket 错误，后续完整负载来自原端口，路径仍有效。

另测新 peer 挤出尾部、容量拒绝、取消提交、关闭其他 flow、真实回调失败与收尾零 pending；账本与旧字节/溢出/失败指标一致。关闭先等待已开始 I/O，再释放底层源。

持续测试进程 CPU 约 1.016/0.875 秒，仅代表本机该测试进程。20ms 是排队容量目标，不是延迟硬保证。本地通过未改变公网 pacing 默认启用 Gate。现用 0.3.2 服务/PID 7108 只读核查仍运行；未加载测试驱动或调整系统网络。

## 后续和回退

pacing 设 0 可关闭。默认继续兼容 FakeTCP，受管 UDP 为显式实验；不扩大队列、不重传业务、不经服务器或成员中继。候选打包与实际交付另行记录。

仍缺方向性负载证据、AutoQuality、兼容/多物理出口调度、完整管线反馈、网卡计账与负载恢复；WAN A/B、60 分钟质量、八真实终端和真实安装/回滚另行验收。不能用本页局部结果宣称 M0—M9 完成。
