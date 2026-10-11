# M5：同源端点 TCP SYN 独立观察

从 `3e88467` 继续。本次交付 M5 观察设施和实验产品接线，**不是 M5 全部完成，也没有取得新的公网打洞正例**。不修改 udp2raw 的 HTTP 前导、bare/SEQ 行为，不增加业务中继、重传或按序等待。

## 实现和正式接线

- `TcpObserverProtocol`：成员签名 + 原网络 HTTPS 身份验证。`catalog/register/read` 使用一个受限 API；不接收任意目标 URL、回调或业务载荷。登记记录 ISS、观察点、ProbeId、启动身份及短时窗。LeaseId/接口/句柄不发送给服务器。
- `TcpSynObserver`：只接受管理员配置的至多两个 IPv4、每 IP 两端口；总计 128 张票，每成员最多保留两张。8 秒观察窗、60 秒结果/冲突保留。完全相同的 HTTP 重试不延长窗口；重复 SYN 去重；同 ISS/目标票据冲突拒绝，同票不同来源标 `Ambiguous`。
- `LinuxSynCapture`：Linux `AF_INET/SOCK_RAW/IPPROTO_TCP`，需 `CAP_NET_RAW`。先挂载并锁定 classic BPF，再声明可用。只接收指定地址/端口、无分片、无载荷的 IPv4 bare SYN；根据实际 IP/TCP 头长过滤，允许中间设备改写/删除选项。最多复制 120 字节头，不持久保存原始报文。观察器不发 SYN+ACK，不改变内核 TCP/防火墙；系统可能正常回复 RST。
- `TcpShapeProbe`：从已存在的 `TcpCaptureOwner` 注册唯一 tuple session，**不第二次 bind P、不创建第二个 WinDivert 捕获者**。SYN 采用既有 MSS/SACK/timestamp/window-scale 外形，无新 option/ProbeId/payload；由 C# 创建报文，经同一受管 WinDivert I/O 发送，不启动 C++ udp2raw 业务握手。这项观察不能替代 C++ SO/HTTP Gate。
- 目标必须避开 helper 的精确 tuple，出口源地址须与 Lease 一致；一时只占一个额外 session。发现已有 Active/Candidate 占用该 tuple 就终止诊断，保留原所有者。每目标最多三包、共至多 12 包，使用全机维护包预算，诊断发送阶段最多 3 秒；整体包含 HTTPS/排队最多 20 秒。等观察窗结束再读取，避免提前漏掉冲突来源。
- `MeshCandidateFactory` 已在正式 TCP 池收集后启动独立后台观察。正常候选立即返回，不等待诊断。每资源最多一次、每 factory 至多八个资源、同时一个任务；失败/取消只释放本任务引用。服务退出先取消并等诊断结束，再关闭池。
- 诊断 HTTP 使用 Runner 既有全机请求桶，服务器也使用原网络/成员限额。`MeshRequestBudget` 加锁以支持该后台调用。实验设置为 `TcpSynObservation=false`；新版连接设置增加开关及后台 capability，旧服务不显示可用能力。必须启用受管 TCP 实验模式才会运行。
- 结果写入本地会话目录 `tcp-syn-observations-<LeaseId>.json`，关联真实源、helper、资源、捕获所有者、接口、出口代次、目标、时间、观察有效期和 ProbeWindowEndsAt。结果不发布为对端候选，也不改变选路。

证据严格分层：`SynObserved` 只表示 ISS/目标/时间窗有限置信关联；`TcpHandshakeVerified`、`LegacyPayloadVerified` 均为 `NotTested`，Filtering 为 Unknown。`NotObserved` 不是“UDP/TCP 被封”或 NAT 类型判定。TCP 数据与 UDP 观察不合并。

## 部署配置（尚未升级现用协调服务）

在原协调服务的独立进程环境设置 `STREAMLINK_TCP_OBSERVER_POINTS`，值为 JSON 数组，例如：

```json
[
  {"Id":"a-1","Endpoint":"192.0.2.10:47221"},
  {"Id":"a-2","Endpoint":"192.0.2.10:47222"},
  {"Id":"b-1","Endpoint":"198.51.100.10:47221"},
  {"Id":"b-2","Endpoint":"198.51.100.10:47222"}
]
```

以上是文档保留地址，必须替换为观察服务器真实接口上的公网地址。当前最小实现只接受本机拥有的地址，不支持把另一台观察机写进目录后自动远程抓包。两 IP 可属于同一服务器；只有一个 IP 时提供局部观察，不分类完整映射/过滤行为。

HTTPS 登记/读取可以继续经过现有域名或 Cloudflare；原始 SYN 必须直达所配置的地址端口，不能经过 CDN/L4 源地址改写。此 raw TCP socket 位于 IP 协议接收路径，需部署者验证主机及上游防火墙允许观察流量；它并不是保证能看到防火墙之前一切报文的网卡抓包接口。本次未添加放行规则。

缺环境变量、平台/权限/配置不满足则只关闭观察能力，协调和现有网络继续运行。`/health` 的 `tcpSynObserver=1` 表示观察器就绪，不表示公网可达。服务端 API 为 `/v3/mesh/{network}/tcp-observer`，沿用签名网络身份。没有持久化票据或新增 MeshLink 密钥。

内核 BPF 的结构、安装/锁定能力依照 [Linux 官方 socket filter 文档](https://www.kernel.org/doc/html/latest/networking/filter.html)；该文档支持的是捕获过滤机制，不提供 NAT 可达保证。

## 本轮验证产物

| `artifacts/` 产物 | 实际范围与结果 |
|---|---|
| `m5-tcp-observer-local-final-20261011.json` | 193 检查通过；30 轮确定性票据状态/归属负例，加一轮真实 HTTPS、独占 TCP helper、内存 broker I/O。覆盖签名伪造、跨成员读取、未配置目标、ISS 冲突、过期迟到、取消和 tuple 抢占。不是 30 轮公网/NAT 验证 |
| `m5-tcp-observer-linux-20261011.json` | VPS 隔离目录、早期固定 60B 过滤版，191 检查通过，实际 Linux raw loopback/BPF；未改生产协调服务 |
| `m5-tcp-observer-wsl-final2-20261011.json` | 最终可变头长版，195 检查通过，现有 ArchLinux WSL 回环实际 Linux raw/BPF；额外确认无关 ACK/端口/载荷被内核拒绝，删除 TCP 选项后的无载荷 SYN 仍可观察。测试后恢复 WSL 原停止状态；并非 Windows 产品依赖 |
| `m5-tcp-observer-windows-wan-r4-20261011.json` | Thinkbook 物理出口 + 真实 WinDivert owner + VPS 公网两端口，单轮 8.729 秒。提交 6 个 SYN；两点均 `NotObserved`。同一 TCP helper 前后公网端点不变且仍可查询，结束后 session 数为 0。**没有取得公网 SynObserved 正例，不证明线上无 RST、SO、FakeTCP 业务或完整 NAT 行为** |
| `m5-observer-runner-regression-20261011.json` | 正式 Runner 55 检查通过：共享 broker/池、TCP/UDP 启动、业务和退出等；使用原生协议测试后端/内存 IP 适配器，不是 Wintun/NAT 真机验收 |
| `m5-observer-app-build-final-20261011.log` | Windows App/Service/Core Release 构建，0 警告、0 错误 |
| `m5-observer-evidence-20261011.json` | 上述产物摘要与 SHA-256 |

公网控制面通过临时 SSH 端口转发进入 VPS 隔离 HTTPS（不承载组网业务）；SYN 直接发向公网 IP。早期三次测试启动失败分别涉及 CLI 工作目录、SSH 监听尚未就绪和临时服务到时关闭，日志单独保留，不能算作 NAT 失败。修正后的 r4 才实际发送 SYN。

VPS `iptables INPUT` 当时为 ACCEPT，但这不足以证明整个上游/本机接收链都放行。随后 SSH 公网及既有组网地址均超时，未完成新增的“原生 SYN 与普通内核 TCP 的捕获计数对照”，因此不能把 r4 无结果归因于校园网 QoS、特定 NAT 或 WinDivert。该对照已加入隔离 harness，待服务器恢复再测。

服务器测试有 150 秒内部期限和 160 秒外部 timeout，临时本地 SSH 转发在 finally 停止。未安装驱动、未修改物理网卡/路由/VMware/Lucky、未替换运行中的 StreamLink 或正式协调服务。诊断文件可能含网络地址，保留在被 Git 忽略的 `artifacts/`，不纳入公开发布。

## 未完成及回滚

- M5 的 ≥20 窗口/留出验证、预测准入、真正预测打洞、有界概率探索未完成，默认关闭；本次不借 UDP 结果填充 TCP 判断。
- 当前诊断等满 8 秒观察窗后读取，适合归属/行为诊断，不满足计划中预测年龄 ≤2 秒的实时准入；后续预测需独立短窗观测/协调，不能直接把本次诊断输出当作新鲜预测。
- 双公网 IP、受控 NAT、真实源端点差异与跨目标连接状态仍待测试。产品后台 hook 已接入并构建，但尚未在现用服务上开启或验证完整常驻任务生命周期。
- 后续继续 M5 条件增强及 M6—M9 独立工作；完整安装包、长期恢复、八真机等原 Gate 保留未通过。
- 关闭 TCP 映射诊断即回到原建链行为；协调服务去掉环境变量即不创建捕获。代码可回到 `3e88467`；新增配置布尔默认 false，未改既有网络身份、数据协议或数据库布局，无数据迁移。
