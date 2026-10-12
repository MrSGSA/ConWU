# M6：按实际出口聚合的受管发送调度

本次保持 FakeTCP＋HTTP 数据 profile、不可靠数据报交付及禁止业务中继。pacing 仍是显式配置，默认速率为 0（关闭）。本改动不宣称增加公网 NAT 覆盖率。

## 正式接入

- `EgressPacer` 先对出口执行字节公平轮转，再对该出口的成员执行字节公平轮转。控制优先额度仍占用原全机速率和队列预算。增加成员、源地址、地址族或网卡不会复制速率额度。
- `TcpCaptureOwner.Session` 和 `PacedTraversalSocket` 已使用该接口；后者继续持有 STUN、检查、提名到业务的原 socket，唯一接收者不变。
- Windows 使用实际绑定源地址和目标地址查询 `GetBestRoute2`，按返回的接口 LUID 聚合；同接口 IPv4/IPv6 共用出口。指定源地址的用法依据 [Microsoft 文档](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getbestroute2)。无法确定的来源并入 `Unresolved`，不生成额外速率。
- 每资源仅缓存 32 组源/目标 IP、最长 5 秒；目标端口猜测不会增加缓存数量。查询在发送器全局锁外执行。该证据描述准入时的 OS 路由，不是物理 NIC 送达证明，也不替代受管出口代次检查。
- 全机仍最多 64 个 Flow、128 个出口/成员分区；Flow 关闭会回收它在所有出口的排队项，并等待已开始的真实发送。正在发送的分区不能被记录清理提前移除。
- 队列仍受约 20ms 发送量和 1MiB 上限约束；目前共用全机上限，因而比各出口分别拥有满额队列更保守。未引入每网卡独立速率配置。
- 状态增加出口队列、峰值、发送量及成员明细；已移除出口的发送量保留在 `RetiredOutletSentBytes`，与当前出口合计对应全机终生发送量。该量仍是本地成功发送调用的外层字节，不是公网有效吞吐。

## 验证与保留的失败

首次回归 `out/m6-egress-outlets-baseline-20261013.log/json` 在混合包长七成员公平性失败。原因是出口额度不足时继续扫描并重复累加成员额度。修复为保留该出口下一成员，只在进入新的出口轮次时补充额度；未放宽公平性或吞吐门槛。

`out/m6-egress-outlets-final-20261013.json/log`：77 项通过。包括两个出口分别拥有六/一成员、出口之间和出口内公平性、全机速率/突发上限、路由变化的排队归属、关闭等待实际发送、在途关闭与记录清理竞争，以及只读 Windows IPv4/IPv6 回环路由。单/七合成成员短时总吞吐约 49.81/49.85Mbps；出口标识的双出口测试使用受控发送回调，不是两条物理宽带。

`out/m6-egress-outlets-sustained-20261013.json/log`：单/七合成成员各 20 秒通过原 98% 吞吐门槛；这是在最终在途记录保护之前的实现证据，后续最终实现另跑上述回归。不得把不同源码轮次合并成同一运行。

正式 Runner 首次运行因独立 checkout 缺少测试过滤器所需 WinDivert DLL 失败，保留 `out/m6-egress-outlets-formal-20261013.log`。从已有主目录复制相同 SHA-256 DLL 后执行过滤器编译及受控原生 I/O 测试；未安装或更换驱动。

`out/m6-egress-outlets-formal-second-20261013.json/log`：145 项通过，真实 HTTPS、Windows TCP helper/UDP、C++ worker 和正式 MeshRunner/MeshLink，完整 1280 字节 IP 双向通信。raw 捕获和内层 IP 适配器为受控夹具，不是 WinDivert/Wintun/WAN 验收。加入在途记录保护后的最终运行 `out/m6-egress-outlets-final-formal-20261013.json/log` 同样为 145 项通过。

## 未完成范围

兼容 `MeshTransport` 原生路径目前有实际注入账本，尚未接入上述 pacing；helper 内核 ACK 是旁路观测与查询准入，不是强制出口整形。M3 完整全机 wire 准入、M6 未受控业务过载反馈及真实多出口测试仍须继续。pacing 不能替代拥塞控制。现用服务、已发布 0.5.5 安装包和生产协调服务不变；总体发布 Gate 保持 `NotPassed`。
