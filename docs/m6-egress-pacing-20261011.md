# M6：受管出口调度（10 月 11 日历史记录）

后续：[10 月 12 日唤醒与突发 A/B](m6-pacing-wakeup-20261012.md) 已修复本地调度吞吐缺口，单/七成员 20 秒测试通过原 98% 门槛；完整链路仍观察到队列溢出和尾部延迟代价，故保持默认关闭。下文保留早期实现与失败证据。

基线 `9920dfe`。本次接入真实发送入口的共享 pacing、按成员字节公平队列及退出清理。**默认关闭，不作为已完成的吞吐优化。** 最近完整本地压测中单成员 49.530 Mbps、七成员 48.876 Mbps，后者未达到 50 Mbps 配置下的 98% 门槛；公网 A/B 尚未执行。

## 产品接入与范围

`ManagedEgressMbps=0` 表示关闭，可配置 1–10000 Mbps。设置页只有后台声明 `EgressPacingVersion=1` 且开启实验打洞时可以修改。单位是外层 IP 比特率，不是应用比特率。配置不改变协议、HTTP/SEQ 或密码会话，也不添加业务重传。

一个正式 `MeshCandidateFactory` 持有一个 `EgressPacer`，TCP 源池中的所有 broker 以及所有 UDP 候选共用它，IPv4/IPv6 不重复分配额度。成员 Device ID 作为公平组，迁移的多条资源也共用该成员份额。当前采用保守的全设备总额度，并未为多 WAN 出口分别配置容量。

- FakeTCP 在 C++ 完成封装后、WinDivert 注入前按完整实际 IP 包长度收费；同一 profile 完整内层包的 IPv4/IPv6 分别为 1446/1466B。
- UDP 在同一绑定 socket 发送前按 payload 加 IPv4 28B 或 IPv6 48B 收费。保留 SocketResourceId、端口、DF 和唯一接收者；1344B 业务帧计为 1372/1392B 外层 IP 包。
- 兼容 native 进程、内核 STUN helper、HTTPS 与网关控制包不在这项 pacing 内，日志和设置明确范围。它不是系统级限速器，也不证明 M3 的全部 socket/原生控制包账本已经完成。
- `SessionStatus.Egress` 提供累计外层字节、当前/峰值队列、容量、丢弃、失败、按成员发送量、队列最大年龄/P95 桶上界、计时等待和令牌截断统计。后台每 30 秒汇总一次，不逐包写日志。

## 队列、时序与生命周期

共享 byte token bucket 的突发预算是 4×1536B。共享排队容量是配置速率约 20ms 的字节量，与 1MiB 取小值；50Mbps 时为 125000B。采用 deficit round robin，按字节而非包数公平。新成员遇到满队列时，只能从排队更多成员的数据尾部置换；没有无限缓存或重发。当前没有按应用截止时间丢弃通用 IP 包。

小 TCP 外形控制包与 UDP 的本地产生控制帧可使用有限优先额度，仍需支付总出口令牌；优先额耗尽后业务优先，不让控制洪泛饿死数据。无法直接识别加密后的 udp2raw 维护载荷，不假称给它们全部分类。

每个 flow 关闭时撤销未发包并等待已取出的那一个发送操作完成，再释放实际 socket/capture。发送前再次检查 native session 的 Start/撤销状态，退役包不能使用重新分配的资源。UDP 控制包保留异步完成与 MessageSize 错误，业务入队不等待跨数据报交付。

Windows 使用独立高精度 waitable timer，没有全局 `timeBeginPeriod`、忙轮询或改变线程优先级。首次实现等待桶完全补满，实测仅约 42.77 Mbps；改为下一个包有资格时唤醒。真实线程延迟仍可能触及桶上限，统计 `BackloggedTokenOverrunBytes` 以暴露这一成本，不能为了追平平均速率偷偷突破突发上限。

约 20ms 是这一级队列的容量目标，并非端到端延迟保证。既有 native pipe/socket 和上游发送队列仍有自身缓冲；本次未证明全管线合计容量，也没有完成多 WAN 聚合、完整拥塞反馈或 AutoQuality。

## 验证与未通过项

| 产物（`artifacts/`） | 结果 | 范围 |
|---|---|---|
| `m6-egress-runner-20261011.json` | 113 检查通过 | 正式 TCP/UDP factory/Runner、实际 C++/TCP helper/IPv4及IPv6 UDP/HTTPS；每承载四种地址族/能力/失败回退组合，关闭后零排队资源 |
| `m6-egress-complete-20261011.json` | 22 个正确性检查通过，最终性能 Gate **Fail** | 真实 Windows 定时器、取消与发送重叠、同 socket UDP、MessageSize、单/七成员饱和、公平性、全机速率/突发包络、控制优先上限 |
| `m6-egress-correctness-20261011.json` | 17 检查通过；性能 NotRun | 上述生命周期/同 socket/控制额度，另补 150 次成员更替和全机 64 flow 上限；没有改变失败的性能门槛 |
| `m6-egress-baseline-20261011.json` | 65 检查通过 | 未开启 pacing 的正式 Runner 基线回归 |
| `m6-egress-settings-20261011.png` | 已查看 | 默认 0、兼容模式禁用输入、界面无控件重叠 |

七成员是同进程受控 flow，并非七台对端或八台真实 Windows。饱和测试由发送回调补充待发数据，以免生产器的粗粒度定时器造成伪吞吐下降；3 秒采样并非长期 A/B。正确性检查保留严格速率上限，性能不足仍以非零退出码呈现，没有修改 98% 门槛。此前 `initial/load/wake/steady/packet-wake/timer` 产物保留用于定位，不能算作通过项。

Runner 的 raw/IP 适配器仍是内存实现，不证明物理 WinDivert、Wintun、NAT 或真实线路可用。无任何现用服务/驱动/网卡配置被替换。保持 `ManagedEgressMbps=0`，待性能原因和 WAN A/B、满载新增成员、长时串流通过后再讨论默认启用。关闭选项并保存可回到现有发送路径；源码回退基线 `9920dfe`。

构建与证据哈希为 `artifacts/m6-egress-manifest-20261011.json`。核心、服务、应用及相关测试 Release 构建无警告/错误。

复现：

```powershell
dotnet build tests/StreamLink.EgressTests -c Release
dotnet tests/StreamLink.EgressTests/bin/Release/net10.0-windows/StreamLink.EgressTests.dll artifacts/egress-new.json
dotnet tests/StreamLink.MeshRunnerTraversalTests/bin/Release/net10.0-windows/StreamLink.MeshRunnerTraversalTests.dll --native out/native/udp2raw-protocol-test.exe --rounds 1 --output artifacts/egress-runner-new.json --egress-only
```

参考：[CreateWaitableTimerExW](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createwaitabletimerexw)、[SetWaitableTimer](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-setwaitabletimer)。高精度能力和实际硬件/线程调度精度需分别验证。
