# 下一版执行状态

规格：[执行计划](StreamLink-Codex-Execution-Plan-20261011.md)，版本 1.0。
开发起点：`aa4023b`；现有工作树干净。此文件随实现更新，未执行的测试不会标记通过。

| 工作包 | 实现/接入状态 | 本轮验证 | 默认启用 |
|---|---|---|---|
| M0 契约与证据 | 最薄 DTO/失败码/统一参数已加入；完整事件接线继续 | Local 入口与独立产物 | 无新增能力 |
| M1 native/Lease 共存 | Core Lease + ABI 1 单 peer 授权、捕获、撤销及 NativeDatagramPath 已实现；共享多 peer broker 未完成 | 两真实 Windows 经旧虚拟接口各 30 轮完整原生 SO/Router；RST 0、helper 未截流；受控 NAT/WAN Gate 待完成 | 否 |
| M2 原生 SO | 状态机及原生路径接入 Router；8 秒期限贯穿原生、认证与提名 | 630 模型；180 轮 C++ 回环故障矩阵；另 30 轮 C++/Router 与两 Windows 各 30 轮 WinDivert/Router；真实 Wintun/WAN 待完成 | 否，须显式受管候选 |
| M3 协商/预算/正式接线 | 正式 Runner 已接收集器、Actor、自动协商、两轻量/一原生准入、HTTP 共用请求桶；broker、兼容资源/原生包总账和完整迁移待完成 | Runner 经真实 HTTPS 各 30 轮 TCP/UDP；准入与完整流程补测 20 检查；TCP 配额/生命周期 247 检查；旧连接 44 检查 | 新模式有实验设置，默认兼容入口；现用部署未升级 |
| M4 UDP_DIRECT/PMTU | 获胜 socket 经 Prepared/Actor 接入 Runner/Router，引用/唯一接收者/SLP2/1344B/DF/共用预算完成；Wintun 与公网 PMTU Gate 待完成 | 既有 30 真实回环 socket 对 + 60 NAT 模型对；另 Runner 自动建链 UDP 30/30，双向 1280B与清理 | 仅显式实验开关，标记质量待验证 |
| M5 观察/条件增强 | 未完成 | 未执行 | 否 |
| M6 质量/效率 | PreferFakeTcp 保护与有界 UDP 队列已接入新 Router；完整选路、pacing/指标待完成 | 健康 FakeTCP 拒绝 UDP 抢占；瞬态压力不重传/不销毁路径 | 保留既有 FakeTCP |
| M7 映射/IPv6 | 未完成 | 未执行 | 否 |
| M8 安全/恢复 | 随各模块实现 | 未执行新增检查 | 保留既有不变量 |
| M9 包/真机/回滚 | 未完成 | 未执行 | 未部署 |

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
