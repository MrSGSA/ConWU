# M8：默认 Mesh 入口的网络通知与 SCM 唤醒接线

本次减少已有失败退避和十秒 helper 定时器带来的等待，保留已验证 FakeTCP＋HTTP 业务路径。不是新的 NAT 穿透算法，也不证明任意 NAT4 组合能直连。Windows 现用服务和生产协调服务未更新。

## 实现

- `MeshNetworkWake` 订阅网络地址/可用性通知；OS 回调只更新有界状态。250ms 静默合并、连续通知最长 1 秒合并、两次交付至少相隔 2 秒。释放订阅后，迟到事件无法重新启动资源。
- `MeshRunner` 在原调度线程处理提示：提前执行失败入口、读取、公告及监听器的下一机会；重置本地失败退避、请求当前 mapping 复核。已在进行的请求继续使用原生命周期；不重置 HTTP、全机控制包或每 pair 的预算。
- 成员传输只清除重试退避，不主动关掉 Active、Candidate、监听器或虚拟网卡。健康路径不会因为网络通知而分配替代原生进程。仍经过既有认证及提名才替换路径。
- `TcpMapping.RequestRefresh()` 使用容量为一的通知额度，提前执行原持有连接的 Pulse；没有关闭后重新 bind P。helper 观察不会覆盖显式 Q 入口。UPnP 续租改为单调时间间隔，避免六次快速观察造成提前续租。
- 正式 Windows 服务使用 `StreamLinkServiceLifetime` 派生现有 `WindowsServiceLifetime`，在启动前开启 `CanHandlePowerEvent`，由 SCM 的三种 Resume 回调交付提示；沿用基础 Host 的启动、停止和关机行为。普通控制台运行保留原 Host lifetime。依据 [Microsoft 的服务电源通知文档](https://learn.microsoft.com/dotnet/api/system.serviceprocess.servicebase.canhandlepowerevent)，不依赖桌面消息循环或用户登录。
- 本地验证脚本和下一次完整打包回归已包含独立网络唤醒、真实 helper 复核，以及后续分支的兼容 native 注入/父进程账本检查。当前只做脚本语法验证，尚未执行此来源的整个打包脚本。

## 本轮证据

| 记录 | 结果 | 范围 |
|---|---|---|
| `out/m8-network-wake-final-20261013.json/log` | 19 项通过 | 正式默认 MeshRunner、加密 UDP 转发路径；受控入口/IP适配器/通知，实际服务回调方法调用；未安装或启动测试服务 |
| `out/m8-tcp-mapping-wake-first-20261013.json/log` | 4 项通过 | 真 Windows TCP/STUN、同连接/源端口/Lease、实际回环 PCP 报文；网关为夹具 |
| `out/m8-network-wake-full-connection-20261013.log` | 81 项通过 | 完整既有 TCP/兼容恢复与调度回归 |
| `out/m8-network-wake-full-mapping-20261013.log` | 356 项通过 | 完整既有 UPnP/PCP/NAT-PMP、续租、通知、helper 失效及回收回归 |
| `out/m8-network-wake-windows-20261013.log` | 100 项通过 | 隔离前台生命周期、DPAPI、互斥、包校验和 UI 操作反馈 |

首次网络提示测试中，五秒退避下的入口约 132.46ms 提前重试；下一提示因共用两秒间隔，约 1092.24ms 交付。真实 helper 测试约 254.28ms 完成新 Pulse，1000 次在维护开始前排队的提示仅产生一次额外 STUN 请求，TCP 连接数保持一、gateway 创建数不增。这些是单次本机受控样本，不是公网恢复时间或 p95/p99；后续同来源重跑保留独立 `final` 记录，不混并样本。

## 仍需继续

- 本次覆盖默认 MeshRunner。历史两槽 `NetworkRunner` 尚未接入这个通知入口。
- 回调方法调用证明产品接线；真实 SCM 派发、睡眠/休眠、物理切网及重启未登录恢复仍未验收。
- 收到通知并不自动证明出口失效；持续健康路径保留。旧探测处于异步 I/O、协调请求被阻塞或新网络尚未就绪时，恢复仍受原超时、资源和预算约束。
- 受管候选已有独立出口代次检查；默认兼容路径的完整路由证据和 stale 探测取消还需继续。不能把快速唤醒代替这些资源语义。
- M3 原生/内核控制包完整准入与账本、M5 条件严格 NAT、M6 兼容 pacing/过载反馈和全部 M9 真实 Gate 仍未完成。总体发布等级仍为开发候选，`NotPassed`。
