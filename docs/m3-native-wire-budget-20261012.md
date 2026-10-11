# M3 原生控制报文计账

基线 `68ba76e`，执行日期 2026-10-12。补上受管 FakeTCP 路径的实际发包计账；不是完整 M3 Gate，也不是严格 NAT 成功率验证。现用安装与默认兼容入口均未替换。

## 产品接线

- C++ worker 在加密前区分 TCP/HTTP/bare 握手、udp2raw 心跳、MeshLink 业务与控制回复；分类只通过已授权的本机 raw pipe 交给捕获所有者。公网 HTTP、SEQ/ACK、密文、包长和数据报语义不变。
- `NativeWireBudget` 在 `TcpCaptureOwner.Session.SendNow`、实际 `Inject` 之前收费；启用 pacing 时在出队后收费。计量为完整外层 IP 帧长度，避免仅按内层载荷少算。
- 同一机器复用 `TraversalResources` 的总账：60pps/burst8、64KiB/s，搜索子账48pps、维护子账24pps。每轮120包/64KiB、24包完成预留。仍使用从原生 Start 起算的同一个8秒期限。
- 共同提名前，任何分类都受该轮限制，包括标为 Business 的帧。只有 Router 收到本路径认证的共同提名结果，才切换为 Active 的业务/维护计账；此后业务不消耗控制配额，心跳及控制报文仍使用全机维护配额。
- 移除该路径上桥接检查、MeshLink 认证/提名、Ping/Pong 的重复收费；UDP和旧后端保留原计账入口。取消、捕获失败、worker退出后禁止注入；旧的8秒轮次不会因再次 Start 或提名而重置。
- 路径状态和原生验证失败诊断带上握手、维护、业务的累计包/字节数及拒绝次数。统计的是注入前被准许的发送尝试，底层注入失败也可能计入，不能当作远端收包数或外侧抓包数。

## 本机协议兼容

原生能力增加 `wireControl:1`。正式实验收集器仅在后端同时声明 `captureBroker:1` 时启用，旧后端明确记录计账范围不足，保留兼容路径。

授权帧原有byte92仍为broker开关；byte93为本机分类开关0/1，94—95必须为0。分类依赖broker，完整授权帧仍由PID、ACL、AttachId、Lease、代次、tuple及回显校验绑定。IPv4 ABI 1与IPv6 ABI 2帧长度不变。

worker→捕获所有者的4字节小端前缀：低16位为40—65535字节的IP帧长度，高16位为Handshake=0、Maintenance=1、Business=2、Completion=3。未协商时高位必须为0；未知类别、保留位、超界长度在分配载荷前拒绝。反方向仍是原有纯长度前缀。无载荷或SYN/FIN/RST报文不能声明Business。该分类是本机受信worker的提示，不是成员认证；成员认证仍由MeshLink完成。

## 本轮证据

产物保存在忽略目录 `artifacts/`，不把测试地址或临时配置提交到仓库。

| 产物 | 结果与范围 |
|---|---|
| `m3-wire-native-build-20261012.log` | 两个原生目标构建；10项协议回归通过，含既有HTTP重叠序号、篡改、重复、丢包、乱序和UDP语义 |
| `m3-wire-first-20261012.json` | 首轮66项通过；七session共享注入账本、三个正式Runner全互连、IPv6/IPv4回退、旧能力兼容 |
| `m3-wire-final-20261012.json` | 最终72项通过，另加raw前缀负例及原生SYN/HTTP实际捕获断言 |
| `m3-wire-reject-20261012.json` | 13组真实子进程/管道拒绝测试；新增无broker却要求分类、未知分类模式、保留位非零；均在首个raw包前退出并保留helper |
| `m3-wire-paced-20261012.json` | 117项通过；正式TCP/UDP工厂、Runner、真实C++及定时器，覆盖pacing出队后计账、IPv6失败回退、旧端兼容与资源回收 |
| `m3-wire-load-20261012.json` | 开启原生计账、关闭实验pacing；两方向各20秒50Mbps输入；见下表 |
| `m3-wire-app-final-build-20261012.log` | 最终应用Release构建通过，0警告、0错误 |
| `m3-wire-router-20261012.json` | 52项受管Router回归通过，覆盖提名、回退、原路径保护、双向健康、撤销与最终释放 |

七个session合用一个源端点的首轮3.007秒注入测试：搜索150包、维护37包，总187包，符合60pps/burst8及48/24子限额。此测试使用真实独占TCP helper、捕获所有者与内存原始I/O；不是七台或八台真实Windows。

三个Runner拥有六条受管路径，共享各自源端点；共同提名后继续等待9秒，确认原轮次已过期而维护仍能发包；再退出其中一个Runner，剩余直连继续传输。辅助TCP与HTTPS是真实本机socket，raw网络和IP adapter为内存适配器。

| 本机回归方向 | 实际接收 | 丢失/重复 | p95/p99 |
|---|---:|---:|---:|
| 一个源→两个peer（合计50Mbps） | 97,621包，49.961Mbps | 0/0 | 5.729/7.931ms |
| 两个peer→同一个源（合计50Mbps） | 97,588包，49.960Mbps | 0/0 | 5.405/6.755ms |

统计使用同机单调时钟及测试尾部收尾窗口。完整1280B内层包经真实Router、MeshLink、C++、管道和回环UDP桥接；没有真实WinDivert、Wintun、NAT或运营商链路。最大交付时间分别24.898/20.239ms。不能据此宣称真实公网零丢帧，也不是与旧版同时进行的延迟A/B。

## 未完成范围与回退

- kernel helper TCP的SYN、ACK、重传，以及旧兼容独立native实例还没有被纳入这套实际IP帧总账；helper应用STUN请求继续沿用原预算。M5诊断SYN有现存应用账本，但若启用pacing，其出队时刻计账仍需统一。
- UDP正式适配器、兼容映射、HTTPS各自已有预算，但全产品各类流量的完整线上统计、维护优先性、八设备压力与完整迁移验收仍待完成。
- 新分类没有增加NAT可达性，不改变上次公网SO未完成的结论。受控30轮、真实八Windows、长时串流等Gate继续保持未通过。
- `scripts/Invoke-TraversalValidation.ps1` 已纳入独立wire检查入口；本次没有声称运行整个Local验证脚本。
- 新能力自动用于匹配后端的实验受管TCP路径；默认`TraversalMode=legacy`及实验pacing默认0保持原值。没有配置格式、密钥或公网协议迁移。现用0.5.0候选仍基于`65e8310`，尚未重打包，不能把本提交当作该ZIP内功能。
- 回退时使用基线`68ba76e`构建的成套托管/原生组件，或切回原兼容模式；不要只替换一个DLL或绕过安装清单。当前现用服务未升级，无需现场回退。
