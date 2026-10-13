# UDP同资源见证与证据等级

现有 UDP唯一接收者、同socket STUN、prflx、完整包PMTU及获胜引用架构未重做。新增 `UdpTraversal.Witness.cs`，在同一持有socket上发96B认证请求，对端响应实际观察到的来源。验证成员方向、当前Attempt、MAC域、请求nonce、来源tuple及本地资源代次；授权限制对端IP，响应无放大，重放表64项、待请求16项，共用现有控制预算与同轮剩余期限。没有selected业务路径也能请求见证；**首个合法包必须真实到达对端**。

回报转换成真实 `NatObservation`，既有 `UdpStableSourceEvidence.PeerPorts`只接受同SocketResourceId/代次/协议/新鲜度/相同映射，并覆盖全部授权目标端口。缺包、缺授权回应者或期限结束返回明确 `PeerPortWitnessUnavailable`。不会通过任意公共STUN端点授权某个私网对端的端口扫描。

`UdpEmpiricalEvidenceProvider`单独给出 EmpiricalEimOnly：训练与后续holdout、独立目标、连续资源与12秒新鲜度、变化映射负例。默认不准入，且永远不是强peer-port证明。此类结果不被现有公共候选schema接纳为强证据。

## 当前证据与限制

本机真实Windows独占UDP socket：两个已认证对端端口回报同一个发送源资源；强证据作用域校验、错误密钥、未授权回应者、接收循环持续、全机资源计账均通过，9项。EmpiricalEim测试的STUN训练/holdout数据是明确夹具，不能算外网探测。首次证据JSON序列化因IPv4 ScopeId抛异常，修为端点字符串白名单后通过，失败日志保留。

**NET-05仍 Partial。** 机制与证据工厂可调用，但正式多成员协商还没有接入PeerPortWitness的准备授权/能力版本/首轮Ready时序。现有生产探索仅能使用已有public-local或测试provider；不能称私网随机NAT探索已可用。双方都没有已可达UDP监听时，见证不可用；不能把“先成功再证明”宣称新增覆盖。EmpiricalEim只提供分级评估，尚未连到独立实验策略开关与正式协商。

后续须接入正式协商后跑算法开关对照，记录每次真实N/M、所用来源资源、完整双向业务与同binary关闭算法的失败。当前没有新增校园网NAT4公网覆盖证据。既有1344B UDP payload DF检查与1400B余量检查的验收仍需用当前固定RC在真实路径重跑。
