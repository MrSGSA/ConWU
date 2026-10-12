# 下一版执行状态

最新接线：[M6有界诊断正式产品流程](m6-diagnostic-product-20261012.md)。独立双端/服务授权、12个方向窗口、共同准备/摘要/结束及业务忙碌撤销已正式进入Factory/Actor/Router/Runner；真实UDP和C++1Mbps低影响联调、390轮控制模型、设置/IPC通过。自动质量判定和共同选择仍缺，AutoQuality拒绝启用；没有更新已发布包或现用部署。全M0—M9发布Gate继续。

当前后续进展：[M6有界负载诊断底层](m6-diagnostic-foundation-20261012.md)。真实UDP及C++诊断额度/发送/接收适配通过，三段5秒原生受控诊断约50Mbps；有一段截止缺口0.033%，不报告公网零丢失。正式诊断协商/Router控制、自动质量比较和共同批准尚缺，AutoQuality仍拒绝启用；整体发布Gate不变。现用服务及已发布0.5.3包未更新。

规格：[执行计划](StreamLink-Codex-Execution-Plan-20261011.md)，版本 1.0。
开发起点：`aa4023b`；现有工作树干净。此文件随实现更新，未执行的测试不会标记通过。

最新实际交付：[0.5.3 私有 GitHub 开发预发行](m9-0.5.3-candidate-20261012.md)，绑定 `02e233e`，约51.84MiB；完整Package、本机/Akane实际EXE281文件、四附件远端digest及版本标签核对通过。包含下述UDP探索正式接入与队列修复，两端现用0.3.2服务及协调服务器未升级。构建源码中的“尚未打包”是当时状态；总发布Gate仍为NotPassed，完整M0—M9目标继续。

最新源码进展：[M6独立备用正式接入](m6-retained-standby-20261012.md)，承接方向业务窗口和认证送达反馈。TCP独立源端点、UDP同一获胜socket、双向认证后的120秒保留、后续共同提名、维护预算、默认关闭的设置/IPC/签名能力和正式Runner已接通。978边界/Router检查、29原生正式检查、9真实UDP正式检查及旧流程回归通过；raw IP和内层网卡仍为内存测试。自动质量比较与切换尚未完成，真实WinDivert/Wintun、公网严格NAT、长期/八真实终端、正式包验收继续。现用服务和已发布0.5.3包未改变；局部进展不能替代M0—M9整体发布Gate。

此前源码进展：[UDP 探索正式产品接入](m5-udp-exploration-product-20261012.md)。独立能力/签名候选、正式 Factory/Runner、同 socket seed 接管、共享准入及设置已完成，默认关闭；90 个本地接入案例和最终准入短回归通过。生产自动资格限于经同源独立目标观察的物理公网 IPv4；私网 peer-port 资格仍缺生产提供者，两端四项 STUN 只作局部观察。下表中局部实现前的历史状态以上述最新进展为准；整体发布 Gate 不变。

| 工作包 | 实现/接入状态 | 本轮验证 | 默认启用 |
|---|---|---|---|
| M0 契约与证据 | 最薄 DTO/失败码/统一参数已加入；UDP 与 native 验证失败关联资源和阶段；完整事件接线继续 | Local 入口与独立产物；原生取消/无对端负例 14 检查 | 无新增能力 |
| M1 native/Lease 共存 | 唯一源端点捕获 broker、授权数据管道、独立 peer worker、源端点池已接入正式实验收集器；兼容 P helper 接入独占 Lease，Q/native 预约明确独占 | 新增63连接检查、30轮/247 Lease检查、11协议用例、356映射检查通过，均本地；既有两 Windows 功能/RST记录保留，嵌套负载未达标；受控NAT/WAN Gate待完成。详见 [兼容所有权](m1-legacy-port-ownership-20261012.md) | 新版兼容入口默认使用独占所有权；SO仍为实验；现用部署未更新；a24f657 候选已包含 |
| M2 原生 SO | 状态机及原生路径接入 Router；8 秒期限贯穿原生、认证与提名 | 既有模型/协议/双 Windows Router 记录；本次增两 Windows 各 1 轮真实 Wintun 功能贯通、各 10 个完整内层包，握手窗口 RST 0；公网 SO 超时、嵌套负载不达标 | 否，须显式受管候选 |
| M3 协商/预算/正式接线 | Runner、broker/池、HTTP与每pair机会窗、受管原生实际注入计账已接；新增兼容MeshLink握手/维护准入、逐成员错峰与状态统计，业务免于低速限额；kernel与兼容原生总账、完整迁移仍待完成 | 10月12日新增Router206、服务70、UDP/预算87检查及Release构建通过；兼容七邻居及300个认证Hello突发验证。先保留集中调度失败证据，再修复，不放宽预算。既有原生负载证据保持，不作为WAN/八真机证明。详见 [兼容控制记录](m3-legacy-control-admission-20261012.md) | 新版兼容MeshLink控制共用预算；受管wireControl仍按能力使用。默认兼容入口、现用部署未升级；a24f657 候选已包含，后续概率探索尚未打包 |
| M4 UDP_DIRECT/PMTU | 获胜 socket 经 Prepared/Actor 接入 Runner/Router，引用/唯一接收者/SLP2/1344B/DF/共用预算完成；Wintun 与公网正例 Gate 待完成 | 既有本地记录；本次真实 Wintun 拒绝 1260 MTU 旧隧道负例；公网两次测试未得到认证包，未进入负载 | 仅显式实验开关，标记质量待验证 |
| M5 观察/条件增强 | TCP 诊断/校准/预测/来源学习已正式接入；UDP 探索能力、签名角色与目标集合、Factory/Runner、同源接管、共享调度及设置已接入。生产稳定资格限于物理原生公网 IPv4；私网 peer-port 提供者与公网预测/探索 Gate 尚缺 | UDP正式接入90案例/494检查、最后35检查短回归、19准入、签名107、watch38、Windows77、基线95及机制38通过；夹具/回环不代表WAN。两真机各四项同socketSTUN仅局部观察。详见 [UDP接入](m5-udp-exploration-product-20261012.md) 和 [TCP接入](m5-tcp-peer-source-product-20261012.md) | 各增强能力独立默认关闭；0.5.2含TCP来源学习，后续UDP探索尚未打包/部署；现用服务未升级 |
| M6 质量/效率 | 选路、恢复、队列观测与受管pacing已接产品；新增业务三阶段时间、真实首包路径和复用普通保活的StablePath。兼容 pacing、完整队列、AutoQuality待完成 | 最终Router203、服务69、基础35检查及Release构建通过；单Router七邻居维护竞争全部完成，确认约4.52–5.86秒，仅本地回环。既有原生负载约49.96Mbps、统计丢失0与paced失败证据均保留；整体质量/WAN Gate未通过。详见 [空闲诊断](m6-idle-path-observation-20261012.md)、[业务恢复](m6-recovery-observations-20261012.md) 与 [pacing](m6-pacing-wakeup-20261012.md) | 新版默认有界恢复观测；pacing默认0、UDP降级独立许可、AutoQuality拒绝启用；a24f657候选已含业务恢复、空闲诊断与兼容控制准入，现用服务未升级 |
| M7 映射/IPv6 | PCP/NAT-PMP TCP/UDP、同 socket UDP IPv6、ABI 2/broker-only FakeTCP IPv6 已接入；有界单播/IPv4组播、共享端口、可让位配额，以及独立于STUN成功的TCP/UDP网关收集完成 | 10月12日最终网关356、正式UDP Runner44、TCP连接46检查通过；全部STUN DNS失败的两个受控Runner约8.798秒直连，真实回环HTTPS/UDP，IP适配器为内存。另有 [组播及配额证据](m7-gateway-multicast-20261012.md)。真实路由器、物理多接口、公网/WinDivert/Wintun/无分片Gate待实测。详见 [独立入口记录](m7-independent-gateway-20261012.md) | 映射、UDP及FakeTCP IPv6均默认关闭；已开启映射的新版尝试通知与独立入口。保留旧成功路线及真实对端认证；现用部署未替换；a24f657 候选已包含 |
| M8 安全/恢复 | 随各模块实现；升级候选与原Active所有者链；新增watch 403后下一预算轮询验证签名撤销 | 10月12日正式工厂/Runner/C++本地集成：360.13秒双端HTTPS中断，692包持续；STUN查询超时后持续；签名撤销5.28秒退出，10检查通过；watch34、基线65通过。raw/IP模拟，真实Wintun/网关/系统生命周期Gate待完成 | 撤销修复无需开关；a24f657 候选已包含；保留既有密码不变量 |
| M9 包/真机/回滚 | 已发布私有GitHub的0.5.3-preview，源码绑定02e233e，含UDP探索接入与队列修复；旧0.5.2/0.5.1/0.5.0包独立保留 | 0.5.3完整Package、本机/Akane实际EXE281文件、四附件远端SHA-256与标签核对通过；安装/冷启动/回滚/八真机Gate未完成。详见 [0.5.3候选](m9-0.5.3-candidate-20261012.md) | 51.84MiB开发预发行，总发布等级NotPassed；Akane独立候选目录，原0.3.2服务未替换 |

本次新增：[M5 有界 UDP 多源探索机制](m5-udp-exploration-mechanism-20261012.md)。确定性模型和真实回环各 30 轮、26 项边界检查、四组各 10,000 种子的纯相交实验通过；普通 UDP 87、Router 206、服务 70、原生计账 74 项回归通过。它尚未接入正式 Runner 资格与协商，不提升 M5/M9 发布等级。

最新 M6 进展：[UDP 发送队列和本地账本](m6-udp-send-queues-20261012.md)。paced 路径去掉前置 128 包队列，立即反馈共享出口拒绝；普通 UDP 包括在途在内受字节/包上限约束；提交至终态的结果接入正式成员/路径状态。61项持续调度、129项正式Runner、673项普通UDP/Router检查通过，单/七合成成员各20秒约49.912/49.903Mbps。首次取消误计失败产物保留；不提升WAN Gate，AutoQuality、完整兼容/多出口账本和系统恢复仍待完成，现用服务不变。

后续源码已接入 [同路径方向性业务窗口](m6-path-traffic-observation-20261012.md)：五秒窗口、最近三窗、有界空闲/业务活动RTT、实际资源及加密会话绑定，正式成员/路径/Runner状态和日志可见。边界16、Router222、正式Runner137检查及Release构建通过；没有新增探测流量，发送入队/真实本地交付分别计数。对端送达/发送损失仍Unknown，AutoQuality及备用路径尚未接入，0.5.3发布包未改写。

后续已接入 [认证路径送达反馈](m6-delivery-feedback-20261012.md)：独立默认关闭、双方/服务授权、实际路径/epoch/序号范围、固定历史/请求上限、现有维护预算及正式设置/Runner。Router反馈34、正式Runner125、签名117、watch40、Windows82、原Router222及构建通过；受控原生双20秒约49.961/49.963Mbps、18段范围报告匹配，非WAN/时限质量Gate。超时/历史不足仍Unknown，不启AutoQuality/备用路径，0.5.3安装包及现用服务未改变。

## 本轮边界

最新实际交付为 [0.5.2 开发预发行](m9-0.5.2-candidate-20261012.md)，绑定 `9775de2`，51.82MiB；完整Package回归、本机/Akane实际EXE281文件预检通过，原服务未安装替换。私有GitHub已推送开发分支，并发布v0.5.2-preview，四个附件的远端SHA-256均已核实。0.5.1记录为上一候选历史，各包均保留；M0—M9整体目标及NotPassed发布Gate未改变。

来源学习已补 [两台真实 Windows I/O](m5-tcp-peer-source-windows-20261012.md)：client/server 各一轮，双端各10个完整1280B回显、接收观察窗口RST0、资源全部关闭；真实Wintun/WinDivert/native/Runner，但公告偏移/helper为受控设置，控制经SSH，业务在已有P2P虚拟链路上。首轮控制TCP超时保留为准备负例。不能据此提升公网、独立冷启动、30轮或八真机Gate；现用0.3.2服务与原网卡未改变。下一候选版本为0.5.2，实际打包结果另行记录。

后续已完成 [TCP 来源学习产品接入](m5-tcp-peer-source-product-20261012.md)：默认关闭的设备开关、原生/双方/协调服务独立协商、签名候选与后续消息权限、正式工厂/Runner、同公网 IP 多成员的真实本地源隔离和安全闲置回收。正式来源28、签名80、HTTPS watch36、Windows71、最终源池41、原Runner92、预测30检查及Release构建通过；raw/NAT/IP仍为受控夹具，未提升公网、物理驱动或八真机Gate，现用服务和安装候选未变。下段“尚未正式接入”为上一机制提交的历史状态。

后续已完成 [原生 TCP 来源端点学习机制](m5-native-tcp-peer-source-20261012.md)：同一授权 IP 的有界 SYN 来源学习，保持 ISS、旧 tuple 预约与原认证，真实身份报告实际端点。两个原生角色各 30 轮及两负例共 793 检查、边界/端点池 38、既有 Runner 92、协议 11 及构建通过。生产配置/签名协商/正式工厂和同 IP 多成员接线尚未完成；当前产品默认不启用，0.5.1 候选未变。

最新独立候选已构建为 [0.5.1-preview](m9-0.5.1-candidate-20261012.md)，绑定 `843dfbd`，约 51.82MiB；完整 Package 回归和本机/Akane 的实际 EXE 281 文件预检通过。已复制到 Akane 新目录，原 0.3.2 服务 Running/Auto 且路径未变。上表 M9 的 a24f657 记录为上一候选历史，不再是最新交付；两包均保留。0.5.1 仍是未通过发布 Gate 的开发候选，未安装。

正式 TCP 预测已补 [反射准备回退](m5-prediction-helper-fallback-20261012.md)，最多三项、总准备期限十二秒，保留独占源/捕获和实际获胜目标。36 项验证包括六类准备结果及两端完整预测链路，Release 构建通过；仍默认关闭，公网 Gate 未提升。

本次继续完成 [TCP 源端点池效率](m3-tcp-source-pool-efficiency-20261012.md)：跨源查询不再共用网络 I/O 锁，七成员可复用同一资源两秒内的观察，保持原始候选时间；取消和失败仍保留 Active 的所有权。30 轮 810 检查、正式 Runner 基线 92 检查、IPv6/回退回归及 Release 构建通过。真实捕获/NAT/多设备 Gate 未因此提升，安装候选未更新。

后续已把正式 TCP 校准/预测与内部 UDP 探索接入 [共享增强调度](m5-shared-enhancement-admission-20261012.md)，校准在采样间隔释放名额，UDP 实际失败按成员对/出口代次冷却。调度31、正式校准43、正式预测20、UDP边界38、服务71检查和Release构建通过；正式 UDP 资格与协商仍未完成，现用部署和安装候选不变。

- 当前计划属于持续开发目标，完成局部提交不代表整个目标完成。
- 不改变已经有效的 HTTP/bare 重叠序号、seq-mode 3 或无业务重传语义。
- 业务禁止协调服务器或成员中继。
- 真实两 Windows、受控 NAT、八终端、长时间质量和未登录冷启动的证据分别记录。
- Local 验证不加载驱动、不操作现用网卡/网络配置；协议回环不能代替 WinDivert。

## 既有可复用证据

以下为各阶段记录。后续接入与候选状态以上表和相应后续文档为准，不把早期“尚未接入”当成当前代码状态。a24f657 候选已经包含兼容独占 Lease、正式预测、独立网关、业务与空闲恢复观测及兼容控制准入；现用服务仍未升级。

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
