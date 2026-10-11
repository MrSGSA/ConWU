# M1 共享源端点捕获与正式 Runner 接入

实现基线 `7b50a55`，执行日期 2026-10-11。本次交付是 M1/M3 的继续实现，不是 M0—M9 或正式发布 Gate 完成。

## 资源与协议

- `TcpCaptureOwner` 为一个实际独占 `TcpEndpointLease` 持有唯一 WinDivert NETWORK 捕获句柄及唯一 native 引用。源 IP:P 固定，双向精确排除 kernel STUN helper 的完整 tuple；不按 PID 分流。
- 不同 peer 仍使用独立 udp2raw C++ worker，避免共享旧协议全局状态。worker 经 ACL、PID 和完整 Attach 帧核对的本机命名管道交付原始 IPv4 TCP 帧，不再重复 bind P、打开重复捕获句柄。
- 每个 worker 有新的 AttachId；共享 CaptureOwnerId。源端口、远端 tuple、代次、Started 状态都参与本机授权。捕获到包不代表成员身份成立；内层仍须经过 MeshLink 路径认证与共同提名。
- 一个 TCP 四元组只能有一个 live/retiring worker。撤销立即停止注入，但直到确认进程退出才释放 tuple；迟到 Start 不能复活已撤销 worker。捕获接收循环退出并确认句柄关闭后才释放源引用。
- HTTP/bare 重叠 SEQ、seq-mode 3、现有密文及业务数据报语义不变；没有引入业务重传、跨数据报顺序等待或成员/服务器转发。

`MeshCandidateFactory` 在实验 TCP 模式、原生 ABI/SO/profile 校验通过且 `captureBroker=1` 时，使用 `MeshTcpEndpointPool`。池按实际源地址与 helper tuple 复用资源；候选只保留自己的引用，native worker 独立保留捕获会话。Runner 先停止 Attempt/Router/worker，再清理池。

辅助查询每 15 秒尝试保活，20B STUN 请求纳入现有共享应用控制预算。查询失效会退役其后续候选能力，保留仍被业务路径使用的捕获；新候选获得新的真实端点。此处**尚未完成 kernel TCP 握手/ACK、全部原生控制包及旧兼容模式的全机线速包总账**，不能据此宣布 M3 预算完整。

未识别 broker capability 的旧原生二进制仍走原单 peer 接入。默认 `TraversalMode=legacy` 未改变，两端现用 0.3.2 服务没有升级。

## 本地验证

`m1-broker-30-20261011.json`：30 轮、570 检查通过。每轮三个真实 kernel TCP helper、四个真实 C++ worker、本机认证管道和 MeshRouter；两个 peer 共用一个源，单个 worker 退出后其他路径继续。原始 IP 报文经内存传递，没有 WinDivert/Wintun/NAT。

`m1-broker-formal-runner-20261011.json`：39 检查通过，新增正式端点池的并发、越权 tuple、撤销、helper 超时替换、最终清理；三组真实 MeshRunner 经正式 HTTPS 协商形成全互连，每组两邻居复用一个实际 helper/capture，退出一组后其余两组继续传输完整内层包。使用内存 IP adapter 和原始报文网络，不能当作三台真实 Windows。

后续增加官方 DLL 的过滤器编译与求值回归：不打开驱动，验证 helper 双向完整 tuple 排除、同 IP 不同端口/同端口不同 IP 不被误排除、其他本地端口与 loopback 不被捕获。统一 Local 入口增加 `native-capture-broker`，总计 18 项；完整运行结果以独立 manifest 为准，不沿用旧 17 项记录。

完整入口已经执行完毕：`artifacts/m1-broker-local-validation-20261011/manifest.json` 的 **18/18 Pass**，源码基线为 `7b50a55` 加本次工作树。包含原生 broker 30 轮/570 检查、原生 Router 30 轮/455 检查、HTTPS/原生协调 30 轮/244 检查、正式 Runner 的 TCP 与 UDP 各 30 轮/合计 217 检查，以及既有协议、MeshLink/连接、提名、UDP 生命周期回归。Runner 的 217 检查包含新增官方过滤器和三组共享源实例用例；这些不是 217 次公网尝试。应用 Release 构建另行通过，零警告、零错误。

## 双 Windows 实际 I/O

隔离目录：本机 `out/m1-broker-network-20261011-a`，Akane `E:\Codex_Workspace\Streamlink\m1-broker-network-20261011-a`。实际 Wintun、生产 WinDivert 原生二进制和共享捕获管道，底层仍为旧 10.129.129.x 网络；只验证真实 I/O，不证明新增公网穿透。

首轮 `m1-broker-wintun-{local,remote}-20261011.json` 失败。原因是新增过滤器使用复合取反，官方编译器在位置 100 返回 parse error，WinDivertOpen 返回 Win32 87。改为等价的 `!= ... or != ...` 后编译通过，未安装、替换或重启驱动。旧失败产物保留。过滤语言及辅助编译 API 参见 [WinDivert 官方文档](https://reqrypt.org/windivert-doc.html#filter_language)。

第二轮使用新身份和新源端口，`m1-broker-wintun-{local,remote}-20261011b.json`：

| 指标 | Thinkbook | Akane |
|---|---:|---:|
| 功能状态 | Pass | Pass |
| 从 Runner 启动到连接（含协调/网卡） | 19832 ms | 19369 ms |
| 完整 1280B 内层回显 | 10/10 | 10/10 |
| 接收端握手/回显窗口 TCP 包 | 39 | 30 |
| 同窗口 RST / 观察错误 | 0 / 0 | 0 / 0 |
| 50 Mbps/20s 请求的实际接收速率 | 37.93296 Mbps | 31.02096 Mbps |
| 报告丢失 | 24.1234% | 37.9452% |
| 全测试捕获队列溢出 | 2713 | 0 |
| 测试结束源资源 / capture | 已关闭 | 已关闭 |

质量状态两端均 Fail，工具退出非零。该测试嵌套旧隧道，不能归因某个 NAT 或 QoS；同时本机 broker 的 2713 次队列溢出是确定的实现侧证据，需在 M6 继续排查管道收发与调度，不能把全部丢失解释为外网。RST 0 只覆盖明确的握手/回显窗口，不代表全程物理外网抓包。

双端本轮完全一致的 Core SHA256 为 `DD747E80ADAFC8C872BBCF24DA97AF518DAF4CA41B51404B5F2C6ED8C2D8754C`；native SHA256 为 `5A0DD422800C6737DEA96A371F73EFFD739D13C5501218DD37847E71F4B45836`。Service/Harness 是同源的前后构建，hash 不同，完整清单分别保存，不能声称整个包二进制相同。

## 清理与后续

`m1-broker-cleanup-{local,remote}-20261011.json`：两端现用 StreamLink 服务 Running；本次目录下测试进程、临时规则和测试 Wintun 地址均无残留。控制服务正常退出并移除规则。没有改 Lucky、物理网卡、VMware、路由器映射或现用隧道。

未完成的 Gate：共享 broker 的真实多 peer/受控 NAT 30 轮、严格 NAT 公网新增 SO 正例、独立公网质量、全机完整控制包核算、可靠切网恢复、八真实终端、长时间负载、正式包及升级回滚。下一步先处理已经量出的本机管道/队列瓶颈，保留旧默认承载；其余 M5—M9 独立工作继续推进。

回滚：现用部署未切换；本次新增 broker 只随实验模式 capability 接入。退回上一实验二进制，或将实验设置恢复 `legacy`，继续使用既有显式入口；无需改动现用网络配置。
