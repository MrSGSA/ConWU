# M3/M4 正式启动流程接线与本地验收

基于 `d5af424`，将已通过协议与引用测试的 `MeshTraversalAttempt` 接入实际 `MeshRunner`。这次不再由测试手工推进 Offer/Ready/Start 或直接向 Router 注入双方上下文。

**实现接入不等于所有 Gate 通过。当前仍为实验能力，未部署现用客户端或协调服务，未制作本轮正式安装包。**

## 产品接线

- `MeshRunner` 异步执行 native 能力预检、Wintun 创建、原入口探测、公告与协商；慢 HTTP 或候选准备不阻塞其他任务。公告与 Router 使用相同 BootId。
- `MeshTraversalManager` 维护每设备一个有界收件箱、合并出站状态和一条已有长轮询。签名、成员、Boot、Attempt 和候选由公共 Actor 校验。接收有效 Offer 后才分配候选资源；Armed 后才发 Ready/Start；共同提名仍经过实际候选路径。
- 较小 slot 发起新轮次。全机最多两个未完成的轻量任务，其中原生 TCP 最多一个；已选路径不占建链并行槽，但仍占真实端点额度。候选创建、取消、异步清理完成后再让出槽位。等待成员按轮转顺序准入。
- 建链机会窗口 60 秒，失败后 30 秒起的退避加抖动，最高约 5 分钟。Native/UDP 激活和提名继续使用原有 8 秒/6 秒剩余期限，没有逐阶段重置。
- 健康旧路径不能被新实验抢占。显式入口先获得 15 秒尝试窗口；未通过验证的入口不能仅靠不断续存公告永久阻止新尝试。无可用直连时不走业务中继。
- 新控制请求、watch、目录与普通公告共用每设备 40 次/分钟、burst 6 的客户端桶；普通请求保留两个额度供控制完成使用。新模式长轮询重新挂起不再固定等 2.5 秒，仍受同一桶约束。取消状态独立保留至发送/到期，不随资源清理直接丢失。

## 真实端点收集器

`MeshCandidateFactory` 由正式 RuntimeServices 调用：

1. TCP 使用独占 `TcpEndpointLease` 建立辅助 TCP STUN 连接，原地观察映射并保留源端点。Prepared native 持有独立引用，不二次 bind 源端口。
2. UDP 由 `UdpTraversal.Create` 取得配额后创建唯一 socket；同 socket STUN 观察，随后交给 Prepared/retained path。成功接入后收集器不关闭已转交的 owner。
3. 每次收集最多尝试列表前三项，整体 12 秒。只发布实际本资源的观察；没有混用 TCP/UDP，也没有把不同端口结果推断为一个端口的 NAT 类型。
4. 在正式收集器中排除回环、无效地址、本网络虚拟子网和已识别的 StreamLink/Wintun/EasyTier 出口；Prepare 时再次确认到对端的路由仍匹配所保留源地址。未覆盖所有第三方 VPN 或代理出口的识别。
5. SO 能力需要 `nativeAbi=1`、WinDivert backend、原 HTTP profile，以及新增 `preparedStart`/`simultaneousOpen` 标志。`--native-info` 不加载驱动；只看到旧 ABI 数字不会误启用新握手。驱动缺失仍在实际 Prepare 阶段失败，不由新收集器自动安装。

TCP 新 Lease 池默认全机 8 个，引用退役后仍计数，最后引用才归还；UDP 沿用全机 8 socket 池。**旧 P→Q 兼容资源与新池的总账、原生 SYN/HTTP/ACK 实际包数、统一 broker 仍待完成。** 当前每 peer 使用不同受管源端点与互斥捕获范围，不声称已实现共享源端点的多 peer broker。

## 开关与兼容

高级连接设置新增 `TraversalMode`：

| 配置 | 行为 |
|---|---|
| `legacy`（默认） | 保留原入口；不启动新 native 能力查询或候选收集 |
| `tcp` | 双方与服务均声明支持时，尝试原生 FakeTCP＋HTTP 双主动 |
| `tcp-udp` | 优先尝试上述 TCP，失败重试可选 UDP_DIRECT；健康 FakeTCP 不因 UDP 建链快而被替换 |

| 同 mesh 协议 4 的组合 | 可用路径 |
|---|---|
| 新客户端 + 新服务 + 双方实验开关开启 | 原入口及双方共同声明的新 profile |
| 新客户端 + 旧服务 | 原入口；没有服务版本确认不发送新控制 |
| 新客户端 + 不声明能力的旧 peer | 原入口；不假定支持 SO 或 UDP_DIRECT |
| 同协议旧客户端 + 新服务 | 原 GET/公告与兼容 watch；不会收到可执行的新能力承诺 |

此表不承诺旧 0.3 配对网络与 mesh 协议 4 混网。失败的显式入口可以退让，健康入口仍保持。健康 UDP 的后台升级与完整质量策略留在 M6，当前不会凭空载 ping 判定它适合串流。

## 验证记录

| 产物/命令 | 结果与范围 |
|---|---|
| `runner-traversal-smoke-20261011.json` | Fail：测试协调服务的 registry 子目录未创建，目录保存返回 500，未进入打洞；补建测试目录后继续 |
| `runner-traversal-smoke-20261011b.json` | 两种实际 Runner 流程各一轮通过 |
| `runner-traversal-30-20261011.json` | **UDP 30/30、原生协议 SO 30/30，180 检查通过**；随后增加单 native 准入和入口窗口规则，另做下行补测 |
| `runner-admission-final-20261011.json` | **20 检查通过**：请求桶、七个等待 peer 的两轻量/一原生准入、撤销清理、15 秒入口窗口、native 能力预检及两种完整 Runner 流程各一轮 |
| `endpoint-quota-20261011.json` | **30 轮、247 检查通过**：原 Lease 生命周期及 8 个保留端点/第 9 个拒绝/最后引用归还配额 |
| `dotnet run --project tests/StreamLink.MeshConnectionTests -c Release` | **44 检查通过**：既有 TCP 映射、旧入口迁移、HTTP 阻塞时的恢复和撤销；没有替换旧测试路径 |
| `dotnet build src/StreamLink.App -c Release --no-restore` | 客户端与服务构建成功，0 警告/0 错误；最后只调整状态提示为中文 |

上述 JSON 位于仓库 `artifacts/`。本次新增测试已加入 `Invoke-TraversalValidation.ps1`，总步骤变为 16；**未把此前的 15 项 Pass manifest 改写成已执行 16 项。**

30 轮记录的时间从完整 Runner 启动到两端状态报告均已直连，包含目录注册、公告、请求预算、准备和约 1 秒状态采样：

| 承载 | p50 | p95 | 最大 |
|---|---:|---:|---:|
| UDP_DIRECT | 6459 ms | 7407 ms | 8540 ms |
| FakeTCP＋HTTP SO | 7442 ms | 7600 ms | 7604 ms |

这些**不是**首个 SYN 到认证的握手耗时，也不是公网冷启动时间。各 profile 首轮短停协调服务 9 秒后继续发送双向完整 1280B 内层 IPv4，并检查 Router/端点最终清理；不将它写成 6 分钟离线或 60 分钟串流验收。

测试使用实际 HTTPS（临时证书 pin、未安装根证书）、正式 MeshRunner/Actor/Router/MeshLink，以及真实 UDP socket/实际 C++ 协议。候选收集器由回环夹具注入：TCP 使用真实本地独占 STUN helper，UDP 使用本机 Host 候选；原生 raw 仍为测试 UDP 通道，IP adapter 为内存实现。**生产公网收集器、WinDivert、Wintun、真实 NAT 和真实八机不在本轮通过范围。**

一次补测构建因同项目 30 轮程序仍占用 Windows apphost 而失败；没有终止验证进程或忽略构建错误，等 30 轮结束后重建并完成补测。

## 尚需完成

- 正式 Wintun 与独立公网双机验收，观察到的端点与实际外层 tuple 对照、真实 RST/helper 验证。
- 共享捕获 broker、旧 P/Q 唯一所有者接入、完整全机包/字节/兼容资源总账，八实例调度压力及真实八设备。
- 新旧路径迁移、硬故障/切网恢复、控制中断至少 6 分钟、未登录启动；当前自动重试和短时控制中断只是局部验证。
- M5 条件 NAT 增强、M6 pacing/质量与稳定恢复、M7 映射/IPv6、M8/M9 安全与正式包验收。

回退：高级设置选“兼容入口”，保存后下一会话使用原路径；本次没有修改配置存储格式、安装服务、路由或现用驱动。代码回退可单独撤销本提交，保留上一提交的公共协调/路径组件；现用部署从未切换。
