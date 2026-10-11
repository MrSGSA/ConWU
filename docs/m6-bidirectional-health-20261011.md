# M6 双向健康与原生验证失败诊断

基于 `0cf92cb`，继续实现执行计划 §9.3；此提交不是 M6 全部完成，也没有部署到两端现用服务。

## 修正行为

此前受管路径的健康判定依赖最近收到的认证报文。一侧持续收到对端业务包，可能掩盖其反向已经不可用的问题。

现在每条受管路径拥有独立、有界的随机挑战记录：维护消息仍使用已有 MeshLink Ping/Pong 格式，在同一个资源收到匹配的认证回复后，才刷新该路径的双向有效时间与 RTT。通过另一候选返回的回复不能刷新此路径；无匹配的重复/旧回复不能刷新。初次共同提名包含真实双向验证，只在首次成功时提供初始有效时间，重复最终确认不能延长它。

保留原 12 秒健康窗口、1.5 秒探针周期作为对照，不冒称已达到 6 秒黑洞发现或 3 秒稳定恢复。每路径最多保留 8 个待匹配挑战，维护发包和响应仍经过全机维护预算；不增加业务重传，不更改 HTTP/bare、seq-mode 3、MeshLink 密钥或业务格式。RTT 从当前 Active 的往返样本读取，避免其他候选污染显示。

Router 单独运行时，健康过期只改变状态，持有者仍有机会收到新的证明。正式 Runner 会看到健康失效并按既有资源清理与退避策略重建；本次没有把测试中同资源恢复直接宣称为产品稳定恢复时间。

## 更明确的原生失败

`NativeDatagramPath` 增加结构化诊断：AttemptId、LeaseId、AttachId、实际本地/授权远端、捕获 Armed、Start 命令确认、子进程是否退出、本机桥接探测尝试数、有效认证探测数、完整载荷资格和本轮剩余期限。

本轮自身超时、worker/pump 中止形成 `NativePathVerificationException`，用于 Runner 的失败日志。调用者主动取消仍为原取消异常，不标记成 NAT 或握手失败。诊断中：

- `StartAcknowledged` 只说明 worker 收到了启动命令，不说明对端 SYN 握手已完成。
- `BridgeProbeAttempts` 是提交给本机 native UDP 入口的尝试，不是物理链路发包数。
- 外层 SYN/SYN+ACK 的完整阶段与线上计数仍需 native 遥测或抓包，不能从零认证载荷推断具体阻断位置。

## 本次验证

| 记录 | 结果 | 范围 |
|---|---|---|
| `m6-bidirectional-router-20261011.json` | 36 检查通过 | 两真实回环 socket、正式 MeshRouter/MeshLink；迁移、重复密文、取消、撤销及新增单向负例。持续送达认证反向业务并丢弃健康回复后，原接收端变为不健康，另一端仍健康；恢复同路径回复后恢复。 |
| `m6-bidirectional-runner-20261011.json` | 20 检查通过 | 原准入/能力检查，以及正式 HTTPS Runner 的 UDP、C++ FakeTCP 各 1 轮，含 9 秒协调中断及完整内层业务。内存 IP adapter、测试 raw backend，不是 Wintun/WAN。 |
| `m0-native-timeout-20261011.json` | 首次夹具失败 | ephemeral raw 测试后端要求注册 token；夹具遗漏导致 child 在准备时退出，没有进入负例。补上 token，没有放宽生产检查。 |
| `m0-native-timeout-20261011b.json` | 14 检查通过 | 实际 C++ test backend：主动取消 167 ms；无对端轮次 8028 ms 退出。接收测试 raw 端观察到 5 个 SYN，本地桥接尝试 40 个，认证 0。失败后 helper 可继续查询，最后引用正确释放。 |
| `m6-native-router-20261011.json` | 30 轮、455 检查通过 | 实际 C++ SO/HTTP、受管 Router、完整内层业务；覆盖交叉/握手单包丢失、HTTP/bare 重叠序号保持、进程退出和引用清理。回环 raw 测试后端，不使用驱动或真实 NAT。 |
| 旧 `MeshConnectionTests` | 44 检查通过 | TCP 映射选择、旧入口迁移、慢协调下恢复/撤销，无现用配置更改。 |
| App Release 构建 | 0 警告、0 错误 | GUI、Service、Core。 |

上述产物保存在本地 `artifacts/`。统一 Local 脚本已加入原生超时负例，总数从 16 改为 17；**尚未完整执行本次 17 项 manifest**，不能使用历史 Pass 替代。

待完成的 M6 内容仍包括：真实负载质量窗口、AutoQuality 迟滞、跨出口公平 pacing、队列年龄、稳定恢复三时间点和公网 A/B。受管路径单向检查的本地通过不替代双 Windows、八终端、冷启动或长期串流验收。保持当前默认兼容入口与安装包不变。
