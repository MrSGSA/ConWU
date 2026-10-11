# 下一版执行状态

规格：[执行计划](StreamLink-Codex-Execution-Plan-20261011.md)，版本 1.0。
开发起点：`aa4023b`；现有工作树干净。此文件随实现更新，未执行的测试不会标记通过。

| 工作包 | 实现/接入状态 | 本轮验证 | 默认启用 |
|---|---|---|---|
| M0 契约与证据 | 最薄 DTO/失败码/统一参数已加入；UDP 与 native 验证失败关联资源和阶段；完整事件接线继续 | Local 入口与独立产物；原生取消/无对端负例 14 检查 | 无新增能力 |
| M1 native/Lease 共存 | 唯一源端点捕获 broker、授权数据管道、独立 peer worker、源端点池已接入正式实验收集器 | broker 内存原始报文 30 轮/570 检查；三 Runner 共享源全互连；两 Windows 真实 broker/Wintun 单轮功能通过、窗口 RST 0，嵌套 50 Mbps 负载未达标；受控 NAT/WAN Gate 待完成 | 仅实验 TCP 模式且 capability 匹配；旧默认不变 |
| M2 原生 SO | 状态机及原生路径接入 Router；8 秒期限贯穿原生、认证与提名 | 既有模型/协议/双 Windows Router 记录；本次增两 Windows 各 1 轮真实 Wintun 功能贯通、各 10 个完整内层包，握手窗口 RST 0；公网 SO 超时、嵌套负载不达标 | 否，须显式受管候选 |
| M3 协商/预算/正式接线 | 正式 Runner、两轻量/一原生、共享 broker/池、HTTP 共桶；新增每 pair 60 秒机会窗、每方法两轮、清理后立即换方法和兼容主动入口计账；兼容资源/原生包总账及完整迁移待完成 | 本次机会窗32、正式基线55、兼容44检查通过；排队也消耗原期限；仅 FakeTCP 首轮故障后第二轮8.647秒成功，4检查；此前30轮记录保留，均非公网/八真机证明 | 新模式有实验设置，默认兼容入口；现用部署未升级 |
| M4 UDP_DIRECT/PMTU | 获胜 socket 经 Prepared/Actor 接入 Runner/Router，引用/唯一接收者/SLP2/1344B/DF/共用预算完成；Wintun 与公网正例 Gate 待完成 | 既有本地记录；本次真实 Wintun 拒绝 1260 MTU 旧隧道负例；公网两次测试未得到认证包，未进入负载 | 仅显式实验开关，标记质量待验证 |
| M5 观察/条件增强 | TCP 同源 SYN 观察协议、成员认证票据、Linux 有界捕获、正式后台诊断与设置已接入；预测/概率增强未完成 | 本地193检查、最终 Linux 回环195检查、Runner55回归；Windows真实物理出口单轮6 SYN，两公网端口均未观察到；不推断 NAT/QoS，公网正例未通过 | TCP 映射诊断默认关闭，需受管 TCP + 服务器能力；现用部署未替换 |
| M6 质量/效率 | 选路、降级后恢复、双向健康及队列观测已接产品；新增受管 TCP/UDP 共用实际外层字节 pacing/成员公平队列；兼容入口 pacing、完整管线队列、AutoQuality 和完整指标待完成 | pacing 正式 Runner113通过，22正确性检查通过但性能Gate失败：50Mbps下单peer49.530、七peer48.876；非公网/八真机；此前双机质量负例保留 | 默认兼容入口不变；pacing默认0关闭、UDP降级独立许可、AutoQuality拒绝启用；现用部署未替换 |
| M7 映射/IPv6 | PCP/NAT-PMP TCP/UDP、同 socket UDP IPv6 已接入；新增 ABI 2/broker-only 原生 FakeTCP IPv6、源所有权和正式 Runner；网关主动通知待完成 | 原生 IPv6 30轮690检查、Runner43、拒绝10组、基线65、UDP54、协议10项通过；真实TCP helper/C++/HTTPS，raw与IP适配器受控；公网/WinDivert/Wintun/无分片Gate仍待实测 | 映射、UDP及FakeTCP IPv6均默认关闭；须服务/双端/后端对应能力及物理地址；UDP另需独立许可；现用部署未替换 |
| M8 安全/恢复 | 随各模块实现；新增升级候选与原 Active 的所有者链及延迟释放 | 本次局部验证升级激活失败、旧路径持续、成功退役和 Runner 退出；其余生命周期 Gate 未完成 | 保留既有不变量 |
| M9 包/真机/回滚 | 已生成0.5.0自包含开发候选、源码包、校验清单/状态/回滚说明；安装前清单检查加固 | 51隔离Windows检查及打包回归通过；本机/Akane实际候选EXE只读核验281文件；未做真实安装/冷启动/回滚/八真机Gate | 发布级别NotPassed；已放入Akane独立工作目录，原服务Running且注册路径未变 |

## 本轮边界

- 当前计划属于持续开发目标，完成局部提交不代表整个目标完成。
- 不改变已经有效的 HTTP/bare 重叠序号、seq-mode 3 或无业务重传语义。
- 业务禁止协调服务器或成员中继。
- 真实两 Windows、受控 NAT、八终端、长时间质量和未登录冷启动的证据分别记录。
- Local 验证不加载驱动、不操作现用网卡/网络配置；协议回环不能代替 WinDivert。

## 既有可复用证据

`docs/pro-review-followup-20261011.txt`：30 轮 Lease 本地生命周期、10 个原生协议检查、40 个 MeshLink 检查、43 个连接检查。均是历史基线，不作为本轮重跑记录。

本轮 M1 证据与未完成项：[受管接入记录](m1-native-attach-20261011.md)。真实 I/O 不依赖关闭现用网络，也不证明公网 NAT 覆盖已扩大。

M3 本次实现与测试边界：[准备与长轮询](m3-preparation-watch-20261011.md)。

共同提名内核与接线约束：[认证模型记录](m3-nomination-model-20261011.md)。

受管 Router 与 UDP 实际适配：[实现与验证边界](m3-managed-router-m4-udp-20261011.md)。

原生 SO/HTTP 到受管 Router 的实际接入及两 Windows 验证：[原生路径记录](m3-native-router-20261011.md)。

签名协调消息与实际 Attempt 接线：[HTTPS 协商记录](m3-control-coordination-20261011.md)。

正式启动流程与收集器的实验接入：[Runner 接线与验收边界](m3-runner-traversal-20261011.md)。

正式 Wintun 双 Windows、物理出口失败与清理：[独立双机证据](m4-windows-runner-20261011.md)。

按路径验证双向健康、超时与取消分类：[M6 局部实现](m6-bidirectional-health-20261011.md)。

共享捕获 broker、端点池正式接入与双 Windows 实测：[M1/M3 继续实现](m1-capture-broker-20261011.md)。

移除逐包进程查询、受控负载与双机复测：[M6 性能记录](m6-broker-performance-20261011.md)。

两种设备策略、签名候选准入、提名竞态及 UDP 降级显示：[M6 产品选路接线](m6-path-policy-20261011.md)。

UDP 降级后的后台升级、混合版本能力、冷却与旧资源保留：[M6 恢复接线](m6-udp-upgrade-20261011.md)。

前台方法切换、共同机会窗、原生第二轮恢复与排队期限：[M3/M6 调度改进](m3-pair-opportunity-20261011.md)。

TCP 同源观察、成员票据、Linux 捕获及公网负例：[M5 观察接线](m5-tcp-syn-observer-20261011.md)。

PCP/NAT-PMP 生命周期、TCP 后备入口及映射失效保留监听：[M7 Provider 接入](m7-port-control-20261011.md)。

UDP_DIRECT 映射、共享控制 socket 和正式自动重试：[M7 UDP 接线](m7-udp-gateway-20261011.md)。

原生 IPv6 UDP、地址族协商、IPv4 回退与未通过的 PMTU 前提：[M7 IPv6 UDP 接线](m7-ipv6-udp-20261011.md)。

ABI 2 原生 FakeTCP IPv6、捕获/校验和、双栈协商与受控 30 轮：[M7 IPv6 FakeTCP 接线](m7-ipv6-native-20261011.md)。

实际封装字节计量、同成员公平队列、正式接线与未通过的性能 Gate：[M6 出口 pacing](m6-egress-pacing-20261011.md)。

安装前路径/哈希检查及来源收据：[M9 打包准备](m9-candidate-packaging-20261011.md)；候选 hash、体积及 Akane 只读验证：[M9 产物](m9-package-result-20261011.md)。
