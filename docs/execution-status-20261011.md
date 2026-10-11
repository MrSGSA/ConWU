# 下一版执行状态

规格：[执行计划](StreamLink-Codex-Execution-Plan-20261011.md)，版本 1.0。
开发起点：`aa4023b`；现有工作树干净。此文件随实现更新，未执行的测试不会标记通过。

| 工作包 | 实现/接入状态 | 本轮验证 | 默认启用 |
|---|---|---|---|
| M0 契约与证据 | 最薄 DTO/失败码/统一参数已加入；UDP 与 native 验证失败关联资源和阶段；完整事件接线继续 | Local 入口与独立产物；原生取消/无对端负例 14 检查 | 无新增能力 |
| M1 native/Lease 共存 | 唯一源端点捕获 broker、授权数据管道、独立 peer worker、源端点池已接入正式实验收集器；兼容 P helper 接入独占 Lease，Q/native 预约明确独占 | 新增63连接检查、30轮/247 Lease检查、11协议用例、356映射检查通过，均本地；既有两 Windows 功能/RST记录保留，嵌套负载未达标；受控NAT/WAN Gate待完成。详见 [兼容所有权](m1-legacy-port-ownership-20261012.md) | 新版兼容入口默认使用独占所有权；SO仍为实验；现用部署与安装包未更新 |
| M2 原生 SO | 状态机及原生路径接入 Router；8 秒期限贯穿原生、认证与提名 | 既有模型/协议/双 Windows Router 记录；本次增两 Windows 各 1 轮真实 Wintun 功能贯通、各 10 个完整内层包，握手窗口 RST 0；公网 SO 超时、嵌套负载不达标 | 否，须显式受管候选 |
| M3 协商/预算/正式接线 | 正式 Runner、共享 broker/池、HTTP 共桶与每pair机会窗已接；新增受管原生SYN/HTTP/bare/心跳在实际注入前共用全机控制预算，提名后业务免于控制限额；kernel与兼容实例总账、完整迁移仍待完成 | 10月12日原生计账72、paced Runner117、Router52、授权拒绝13组、协议10项通过；本机50Mbps两方向各20秒约49.96Mbps且报告丢失0；均非公网/八真机证明，详见计账记录 | 匹配wireControl能力的实验TCP自动使用；默认兼容入口，现用部署未升级 |
| M4 UDP_DIRECT/PMTU | 获胜 socket 经 Prepared/Actor 接入 Runner/Router，引用/唯一接收者/SLP2/1344B/DF/共用预算完成；Wintun 与公网正例 Gate 待完成 | 既有本地记录；本次真实 Wintun 拒绝 1260 MTU 旧隧道负例；公网两次测试未得到认证包，未进入负载 | 仅显式实验开关，标记质量待验证 |
| M5 观察/条件增强 | TCP 同源诊断、独立校准及四种模型完成；新增正式签名预约/观察协商、八端口原生窗口与 Runner 接入，首次注入按两秒单调时钟领取，整轮八秒共用观察/握手预算；概率策略与公网预测 Gate 未完成 | 10月12日新增受控正式 Runner 四轮及五类准入负例共25检查；签名66、模型58、原生计账74、观察270、既有Runner79、Windows设置65通过。真实HTTPS/helper/C++，NAT/IP和训练窗口为明确标记的模型，不代表公网预测成功。详见 [接入记录](m5-prediction-runner-20261012.md) | TCP诊断、校准和预测各自默认关闭；实际预测须双方/服务能力与校准资格；现用部署、当前安装候选仍未包含本次接入 |
| M6 质量/效率 | 选路、降级后恢复、双向健康及队列观测已接产品；受管 TCP/UDP 共用 pacing；新增发送线程/突发 A/B 后修复本地吞吐缺口。兼容入口 pacing、完整管线队列、AutoQuality 和完整指标待完成 | 10月12日20秒单/七peer为49.809/49.871Mbps，28检查通过；正式paced Runner117通过。真实C++链路约49.932/49.961Mbps，但单出口57包溢出且P99增大；本地调度性能通过，整体质量/WAN Gate未通过。详见 [后续记录](m6-pacing-wakeup-20261012.md) | 默认兼容入口不变；pacing默认0关闭、UDP降级独立许可、AutoQuality拒绝启用；现用部署与安装包未替换 |
| M7 映射/IPv6 | PCP/NAT-PMP TCP/UDP、同 socket UDP IPv6、ABI 2/broker-only FakeTCP IPv6 已接入；有界单播/IPv4组播、共享端口、可让位配额，以及独立于STUN成功的TCP/UDP网关收集完成 | 10月12日最终网关356、正式UDP Runner44、TCP连接46检查通过；全部STUN DNS失败的两个受控Runner约8.798秒直连，真实回环HTTPS/UDP，IP适配器为内存。另有 [组播及配额证据](m7-gateway-multicast-20261012.md)。真实路由器、物理多接口、公网/WinDivert/Wintun/无分片Gate待实测。详见 [独立入口记录](m7-independent-gateway-20261012.md) | 映射、UDP及FakeTCP IPv6均默认关闭；已开启映射的新版尝试通知与独立入口。保留旧成功路线及真实对端认证；现用部署/安装包未替换 |
| M8 安全/恢复 | 随各模块实现；升级候选与原Active所有者链；新增watch 403后下一预算轮询验证签名撤销 | 10月12日正式工厂/Runner/C++本地集成：360.13秒双端HTTPS中断，692包持续；STUN查询超时后持续；签名撤销5.28秒退出，10检查通过；watch34、基线65通过。raw/IP模拟，真实Wintun/网关/系统生命周期Gate待完成 | 撤销修复无需开关；已有发布包尚未重打；保留既有密码不变量 |
| M9 包/真机/回滚 | 已刷新0.5.0自包含候选至f648059，包含新撤销/计账/预测观察；摘要必须绑定源码，旧包独立归档 | 10月12日完整打包回归通过；本机/Akane新包实际EXE只读核验281文件、ZIP哈希一致；未做真实安装/冷启动/回滚/八真机Gate | 51.75MiB开发候选，发布级别NotPassed；Akane新独立目录，原0.3.2服务Running且注册路径未变 |

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

已知可达目标端口的真实公网 SYN 观察与同资源映射差异：[M5 公网补测](m5-public-observer-followup-20261012.md)。

PCP/NAT-PMP 生命周期、TCP 后备入口及映射失效保留监听：[M7 Provider 接入](m7-port-control-20261011.md)。

UDP_DIRECT 映射、共享控制 socket 和正式自动重试：[M7 UDP 接线](m7-udp-gateway-20261011.md)。

原生 IPv6 UDP、地址族协商、IPv4 回退与未通过的 PMTU 前提：[M7 IPv6 UDP 接线](m7-ipv6-udp-20261011.md)。

ABI 2 原生 FakeTCP IPv6、捕获/校验和、双栈协商与受控 30 轮：[M7 IPv6 FakeTCP 接线](m7-ipv6-native-20261011.md)。

实际封装字节计量、同成员公平队列、正式接线与未通过的性能 Gate：[M6 出口 pacing](m6-egress-pacing-20261011.md)。

安装前路径/哈希检查及来源收据：[M9 打包准备](m9-candidate-packaging-20261011.md)；候选 hash、体积及 Akane 只读验证：[M9 产物](m9-package-result-20261011.md)。

协调中断六分钟、反射查询失效、签名撤销正式修复：[M8 生命周期](m8-control-lifecycle-20261012.md)。

原生SYN/HTTP/心跳全机计账、正式提名接线及受控负载：[M3 原生计账](m3-native-wire-budget-20261012.md)。

条件预测、单调新鲜度、短窗口公网来源观察与仍待完成的产品协商：[M5 预测与短窗](m5-prediction-short-observer-20261012.md)。

摘要源码绑定、完整重建、最新候选哈希与 Akane 只读校验：[M9 候选刷新](m9-candidate-refresh-20261012.md)。

正式 TCP 独立源校准、目标恢复取消、共享排队与默认关闭设置：[M5 校准收集器](m5-independent-calibration-20261012.md)。本轮工厂36、模型58、Windows界面/生命周期58、默认关闭Runner基线68检查通过；观察/NAT为受控夹具，不代表公网预测成功。最新打包候选尚不含此后续提交。

原生端口窗口、共用120包/8秒预算、首包前领取、并行准备、获胜资源转移：[M5 原生窗口](m5-native-port-window-20261012.md)。最终三端口各30轮746检查、八端口各1轮50检查、原有计账72与IPv6 broker23检查通过；真实helper/C++/Router/MeshLink，raw与IP为内存适配。正式签名预测协商和工厂自动选用仍未接入，现有默认路径及安装包未切换。
