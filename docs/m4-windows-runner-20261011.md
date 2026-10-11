# 双 Windows 正式 Runner / Wintun 隔离验证

基于 `3962c58` 和本次未提交的验证工具，2026-10-11 执行。两端现用 0.3.2 服务没有停止、升级或替换；Lucky、路由器、VMware、排除端口和现用虚拟网卡 MTU 没有修改。

## 实现和测试范围

新增 `StreamLink.MeshHarness traversal-prepare/traversal-run`，运行真实 `MeshRunner → Actor → Router → MeshLink → Wintun`。TCP 使用实际 WinDivert 生产二进制；UDP 使用实际唯一 socket。通过正式 HTTPS MeshRegistry 路由进行签名 Offer/Ready/Start 协商，不手动设置 Router Active。

测试模式分别为：

- `host`：从当前旧组网地址收集测试候选；TCP helper 和新 FakeTCP 使用同一个实际源资源。业务嵌套在现用隧道中，**不证明新增公网打洞**。
- `public`：调用产品的 `MeshCandidateFactory`，从物理出口查询公共 STUN，使用所得候选尝试新链路。旧隧道只用于协调 HTTPS 和 SSH。禁用测试内的旧入口/UPnP 探测，不改路由器映射。

每轮使用独立网络身份、Wintun 和会话目录，限时 100 秒。连通后先双向各回显 10 个完整 1280 字节内层 IPv4 包，再顺序执行每方向 50 Mbps/20 秒。`Quality` 统计含一秒收尾，不代表迟到率、p95/p99 延迟或 60 分钟验收。

控制服务绑定现有虚拟 IP 的一个指定端口，临时证书 pin，未安装根证书；只有协调 API，没有业务转发接口。host 防火墙只允许指定对端、地址、端口和协议，退出即移除。

## 本轮实际结果

| 测试 | 结果 | 解释 |
|---|---|---|
| UDP host 初轮 | 启动失败 | 58401/58411 落在本机 Windows UDP 排除范围 58316–58415。无监听不代表端口可 bind；未修改排除范围。改用双方实际 bind 预检通过的 444xx 测试端口。 |
| UDP host 第二轮 | `mtu-too-small`，未选中路径 | 当前旧 overlay MTU 1260，而新 UDP 需要 1344B payload / 1372B IPv4，DF 开启。正确拒绝，未关 DF、降低门槛或改旧网卡。 |
| TCP host | 两端功能贯通 | Thinkbook 15334 ms、Akane 13173 ms 报告已连接，均含完整启动与协调；各 10/10 完整内层包回显。各接收端握手/回显窗口 41 个 TCP 包，RST 0，SYN+ACK 1，观察器 error 0；最后资源关闭。只有一轮，不能替代 30 轮 Gate。 |
| TCP host Akane → Thinkbook 负载 | 39.36144 Mbps，21.2441% 丢失 | 请求 50 Mbps；未达质量目标，嵌套旧隧道不能作为独立公网回归。 |
| TCP host Thinkbook → Akane 负载 | 31.24368 Mbps，37.4906% 丢失 | 同上。未据此修改已有数据 profile，也未归因某种 QoS。 |
| TCP public | 两端各两轮激活超时 | 候选观察和 native 授权完成，但未完成验证路径；旧日志只有取消异常。未抓到完整外层双向证据，不能据此断言 NAT 类型或具体 SYN 拦截点。 |
| UDP public 初轮 | 两端各两轮 `no-verified-path` | 未建立业务，未运行负载测试；失败不能归为带宽不足。 |
| UDP public 诊断补轮 | 两端各两轮 `no-verified-path` | 每轮每端 30 个已计数发送、0 个认证检查包、0 个学到的新候选；实际检查约 6.1–6.2 秒。只证明当前候选未完成认证，未定位 NAT、主机防火墙或中间过滤的责任。 |

`TCP host` 当时的原始 JSON `status=Pass` 仅表示功能流程完成并取得质量报告，**不表示质量通过**。保留原始文件，不改写历史产物。后续工具已经分出 `functionalStatus`、`loadStatus`，并以至少 49 Mbps 且零报告丢失作为该短负载检查的明确门槛；不达标会退出非零。此门槛是测试工具条件，不是公网保证。

## 证据和构建

本地 `artifacts/`（不提交带实际端点的默认诊断数据）：

- `m4-udp-wintun-remote-20261011a.json`：首轮端口失败时的远端超时。
- `m4-udp-wintun-{local,remote}-20261011b.json`：真实 DF/MTU 负例。
- `m4-tcp-wintun-{local,remote}-20261011.json`：完整 TCP/Wintun、短负载及握手头部观察。
- `m4-tcp-public-{local,remote}-20261011.json`：物理出口 TCP 未通过。
- `m4-udp-public-{local,remote}-20261011.json` 和 `...20261011b.json`：两次 UDP 结果。
- `m4-network-cleanup-{local,remote}-20261011.json`：测试结束状态与实际二进制 hash。
- `m4-udp-diagnostics-regression-20261011.json`：协调/Attempt 34 检查通过；不是公网测试。

本次实际两端负载相同的关键 SHA256：

| 文件 | SHA256 |
|---|---|
| `StreamLink.Core.dll` | `6EAFF1D3383D460D759C79177224C85639784D9C54D31BA3280E0F640CC2FE44` |
| `StreamLink.MeshHarness.dll` | `260DDF31B662B604BC268473952709F72B63397FA43F1945A80371D06EDECB02` |
| `udp2raw-native.exe` | `753688D8D541CD5FFCC106E7F7533A477BBA141F94C25F9537BAC4C96BAFDF06` |

Harness 是 .NET 10 self-contained win-x64，仅放在独立测试目录，不要求对机安装运行时。远端目录为 `E:\Codex_Workspace\Streamlink\m4-runner-20261011-a`。源码随后增加质量判定与环境清单，不能把上述旧 hash 当成未来构建的 hash。

复现入口：构建 `tests/StreamLink.MeshRunnerTraversalTests`；使用 `--serve <明确绑定IP> <端口> <新目录> <最多1800秒>` 启动临时控制服务。publish MeshHarness 并放入正式 components 后，用 `traversal-prepare <目录> <coordination.json> <本机IP> <对机IP> tcp|udp host|public` 生成一次性配置，分别执行 `scripts/Invoke-TraversalNetworkNode.ps1 -Configuration <本端private.json> -Output <新结果路径>`。配置信息包含临时网络密钥，不进入公共产物。源文件夹提供的控制 `stop` 文件可优雅结束协调服务。

## 清理、剩余 Gate 与回滚

本轮终态已核对：两端现用服务 `Running`；测试 Harness 数为 0；测试 Wintun 和 `StreamLink-M4-*` 防火墙规则无残留；本机 44491 控制监听已关闭。控制服务进程正常退出。测试私有配置只在被 git 忽略的隔离目录中，未改写现用凭据。

M1/M2 完整 Wintun 的单轮功能证据已经增加，但 30 轮受控正例、真实公网新增 SO 成功、独立公网质量仍未通过。M4 公网及真实双端 Wintun 正例没有通过。共享 broker、TCP 多目的实际观察、有条件 NAT 增强、双向健康及完整恢复、八真实 Windows、60 分钟质量、正式包和升级回滚继续推进。现有入口仍为默认；没有发布或替换生产安装包。

回滚本轮测试不需要改用户配置；部署未切换。后续试验前使用新输出路径与临时身份，先确认旧进程已退出，不能通过重复绑定或强抢端口消除系统错误。
