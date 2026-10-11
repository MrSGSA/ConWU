# M3：共同提名认证内核（接线前验证）

本次新增 `PathNomination` 和 MeshLink 控制类型 7。**尚未接入正式 Router 的路径切换与资源持有，不算 M3/M4 Gate 通过，不默认改变业务选路。**

## 语义

- 每成员仍只有一个 MeshLink 密码会话、发送计数器和重放窗口。提名、旧路径和新候选共享它；重试重新编码控制包，不重发相同密文。
- 控制 body 80 字节，必须在经过认证的 MeshLink type 7 中使用。与内层 IP 业务类型分开，不能作为数据投递给网卡。
- 上下文摘要绑定网络、按身份排序的双方 NodeId/BootId、候选 ID/版本、AttemptId、profile、相反的协议/提名角色和验证 nonce。
- 每轮还绑定本地真实收包 PathId 和单调增加的 NominationRevision。旧路径返回的有效密文不能证明 Candidate 可达。
- 双方完成 Check/CheckReply，且候选已经具备 MTU 证据，才进入 Prepared。
- 提名方发送 Nominate；响应方确认后返回 Confirm；提名方取得 Confirm 才申请切换并发送 Commit。响应方取得 Commit 后申请切换并返回 CommitAck；提名方取得 CommitAck 才记录对端已经采用本提名。
- 调用方须先执行申请的本地切换，再发 Commit。因此状态机不能单独取代 Router。
- 使用调用者传入的剩余期限，SO 不超过 8 秒、UDP 不超过 6 秒；不会在 MeshLink 阶段重新获得整轮期限。
- Cancel 是终态。超时最多再发送 3 个清理取消通知，不延长认证窗口；清理消息仍须经过统一控制预算。

## 切换接线必须补齐的约束

`SwitchRequested` 不是资源释放许可。正式调用方必须：

1. 在 Ready 前取得资源与预算；校验协商能力、成员身份及实际 tuple。
2. 候选检查期间持续使用原有健康 Active；切换前持有新路径引用。
3. 只有取得对端采用证明后，才启动旧路径的 2 秒接收宽限；共用 MeshLink 重放状态消重。
4. 保留可回退的旧资源直到本轮确认/清理收敛。取消或提交证明缺失时恢复原 Active；不得关闭其他成员引用。
5. 全丢 CommitAck 与取消又丢失时，需要最终状态重同步或更高 revision 的新 Attempt；不能声称分区中原子一致。
6. 同一真实 TCP tuple 不并行运行两套 ISS/IRS；单一捕获 owner 也不能替代这个协议约束。
7. 默认 PreferFakeTcp，健康 FakeTCP 不因 UDP 更快通过检查而被替换。

以上仍是后续 Router/Transport/Runner 接线工作，并未借本次模型测试标记完成。

## 证据及范围

`tests/StreamLink.NominationTests`：9 类机制各 30 轮，使用真实 MeshLink AES-GCM/计数器/重放逻辑和可控单调时钟，注入普通成功、单次 Confirm/Commit/CommitAck 丢失、对应消息持续丢失、错误实际承载、MTU 未合格。

另有上下文字段逐项变更、旧 revision、已取消轮次、200ms 剩余期限、会话建立前控制、密文篡改、重启旧 epoch 负例。模型中持续交错发送 1280 字节载荷，控制丢包不阻塞后续数据报。

这证明认证状态机约束；**没有调用 Router、NativeAttachment、WinDivert、真实 NAT 或 Wintun**。大量断言来自逐包检查，不能当成独立拓扑覆盖或公网成功率。

统一 Local 验证入口现纳入 10 个构建/测试步骤，产物保持各自 scope。安装包、两机公网迁移和真实八终端验收仍在后续阶段。

本轮统一产物：`artifacts/validation-m3a-20261011/manifest.json`，10 步通过，基于 `cadc33c` 上的开发工作树（dirty=true）。其中 `nomination-model.json` 为 270 轮认证模型。登记竞态补丁另由 `artifacts/mesh-watch-registration-20261011.json` 的 24 项检查复核。
