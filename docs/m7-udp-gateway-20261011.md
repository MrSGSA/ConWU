# M7：UDP_DIRECT 网关映射正式接线

后续补充：[独立网关收集](m7-independent-gateway-20261012.md) 已解除网关轮次对 STUN 解析成功的依赖；本页保留初次接线的历史证据。

从 `63d09a2` 继续，将上一轮 PCP/NAT-PMP Provider 接入 `MeshCandidateFactory → UdpTraversal → Prepared → MeshRunner → MeshLink`。本次仍未使用真实路由器或 Wintun，不能据此声称公网 NAT 覆盖扩大。FakeTCP+HTTP 数据 profile 和禁止业务中继的约束保持不变。

## 收集与选路

`PortControlMapping` 继续默认关闭。后台能力 `PortControlVersion=2` 表示同时具有 TCP 后备入口和本次 UDP 收集能力；新版界面据此显示通用映射选项，遇到能力 1 仍显示“TCP”。它不会单独开启 UDP，正式 UDP 仍要求 `tcp-udp` 实验模式、允许 UDP 降级以及既有双方能力协商。

每个成员的首次 UDP 收集使用普通同 socket STUN，后续收集在普通方式与显式映射之间交替。在调度器进入下一轮时才切换收集来源，不会在已经公布的 socket 上突然申请另一条映射。健康 FakeTCP 不受影响；映射成功也不直接进入 Active。

映射轮次为实际持有的 UDP 数据端口申请 **UDP** 租约，不传递端口数字后重新 bind。网关返回值仍经过生产出口/公网 IPv4 检查，内层私网、CGN 地址不能发布为公网入口。公告的 ObservationTarget 是实际网关，Expires 不超过授予租约剩余时间或 120 秒上限；过短租约不进入准备阶段。

收集沿用 12 秒期限，并计入原有 60 秒成对机会窗。取消后等待创建任务/精确清理结束，下一轮仍使用剩余机会窗；不会重置超时以掩盖耗时。前台取消不把网关永久标成“不支持”。网关事务失败后不通过切换 STUN 域名重复同一映射请求。

当前仍通过一个已解析的 STUN 目的地址选择本机物理出口，但映射轮次不要求该 STUN 服务回复。完全脱离 STUN 域名解析的出口收集尚待实现。普通第一次失败可能消耗数秒，因此显式开启该后备策略不承诺比已可达的普通 UDP 更快。

## 生命周期与资源

- `UdpTraversal.AttachGateway` 检查协议、精确本地 IP:port 和 socket 状态；只有成功返回才转移租约所有权。TCP 租约、其他端口的 UDP 租约、已开始握手或已转交的 socket 均不能冒用此入口。
- `UdpGatewaySnapshot` 在本地把租约状态关联到 `SocketResourceId`。没有把句柄、nonce 或本地 LeaseId 塞入公开候选。
- 维护任务使用 socket 所有者的结束令牌，不使用 Gather/Attempt 的短期令牌。原 owner/Prepared 结束后，获胜路径仍持有 socket 引用，租约继续维护。
- Candidate、Prepared.Armed、Activate 和 RetainPath 都检查冻结的网关端点是否仍有效。续租返回不同端口或 epoch 失效后，旧 Offer/Ready/Start 不能用新地址激活；后续轮次重新收集。
- 已认证 Active 不因租约元数据失效直接关闭。继续由 Router 的实际双向健康判断可用性；如果真实 NAT 状态已经失效，业务检查仍会触发正常恢复。本次回环正例不能证明过期的真实 NAT 仍会转发。
- 最后一个路径/收包引用释放后，先取消并等待网关维护、执行所有权匹配的清理，再释放数据端口，避免异步删除时端口已经交给另一实例。NAT-PMP 仍只等待租期到期，不发删除。

Provider 现在按 **源地址 + 网关 + 路由代次** 共享一个 connected UDP 控制 socket，所有事务串行并严格匹配 nonce/协议/内部端口。它与数据 socket 分离，但同样计入全机八 socket 额度和维护包桶。不同租约不能通过另一个资源账本复用该所有者。最后一个租约退出才释放控制 socket。

因此，同一出口/网关下，七个 UDP 数据 socket 加一个控制 socket 可以刚好使用八个额度。此时没有额外迁移 socket 的余量；多出口可能需要多个控制 socket，也会更早耗尽预算。没有为每个 peer 复制八 socket 额度，也没有提高默认上限。这里验证的是本模块受管的持有资源；既有 `Stun.LocalAddress` 临时无发包路由查询 socket、兼容层等全进程资源总账仍属于 M3 未完成项。NAT-PMP 留在网关上的未过期规则不等于仍占用本地 socket，诊断应区分这两者。

## 验证与边界

新增测试运行真实 Windows UDP/TCP 用户态 socket、PCP/NAT-PMP/STUN 报文和本地 HTTPS 协调；网卡为内存适配器。仅测试中允许回环候选并注入回环网关，生产配置没有关闭路由检查的入口。

| 产物 | 范围 |
|---|---|
| `artifacts/m7-udp-gateway-20261011.json` / `.log` | 25 项新接线专项通过。七个绑定数据 socket 共用一个控制 socket；错误资源账本/协议/端口拒绝；原 Attempt 释放后同资源传输 1344B；映射变化后旧准备拒绝。正式双 Runner 的第一次 STUN 候选被引向夹具持有的黑洞端口，真实检查失败后自动进入第二轮，分别通过 PCP 和 NAT-PMP 候选完成认证及双向 1280B 内层 IP 传输。再丢弃续租响应，验证租约过期不直接关闭仍能通信的路径。 |
| `artifacts/m7-udp-gateway-mapping-20261011.json` / `.log` | 276 项原映射回归，含共享串行排队过期、取消、nonce、错误退避、TCP helper 分离与清理。本次输出独立文件，保留上轮原始证据。 |
| `artifacts/m7-udp-gateway-managed-20261011.json` | 35 项 UDP Router 冒烟回归：真实回环 1 轮、NAT 行为模型 2 轮。未抓取线上 DF/分片，不替代实际 PMTU Gate。 |
| `artifacts/m7-udp-gateway-baseline-20261011.json` | 55 项正式 Runner 基线，含三实例、共享 TCP 捕获资源与普通 TCP/UDP 业务；使用原生协议测试后端，不加载驱动。 |
| `artifacts/m7-udp-gateway-settings-20261011.png` | 新能力标签预览；默认未开启映射。 |

专项的精确耗时、检查数及 socket 身份保存在 JSON。本轮 15.203 秒的自动连接包含第一次故意失败、控制协商和第二轮，属于回环单轮证据，不是校园网 p50/p95 或 NAT 类型成功率。七个本地数据 socket 的预算验证不是八台 Windows 验收。

应用、服务和相关测试 Release 构建通过。哈希清单：`artifacts/m7-udp-gateway-manifest-20261011.json`。测试命令：

```powershell
dotnet tests/StreamLink.MeshRunnerTraversalTests/bin/Release/net10.0-windows/StreamLink.MeshRunnerTraversalTests.dll --native out/native/udp2raw-protocol-test.exe --rounds 1 --output artifacts/m7-udp-gateway-20261011.json --gateway-only
dotnet tests/StreamLink.TraversalTests/bin/Release/net10.0/StreamLink.TraversalTests.dll --managed-smoke artifacts/m7-udp-gateway-managed-20261011.json
```

## 待完成与回滚

实际网关发现/映射、外层 NAT、Wintun 到公网业务、网关主动更新通知和完整原生 IPv6 仍未通过本次 Gate。M7 不能标为全部完成，也不默认启用映射或 UDP 降级。

关闭映射选项后保存，恢复普通 UDP 收集和原 TCP STUN/UPnP 路线；保存按产品已有行为重连。仅要回退 UDP 接线，可回到 `63d09a2`，保留上一轮 TCP Provider。新代码没有新增 profile 字段或数据库迁移；共享控制 socket 仅在进程内存在。停止当前版本时等待其路径和租约清理，PCP 删除未确认、NAT-PMP 未过期均如实记录，不删除无关网关规则。本轮未替换已安装服务或更改网络配置。
