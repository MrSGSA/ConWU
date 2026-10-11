# M3 认证协商与正式路径的连接

基于 `7aebf18`，新增有类型的协调消息及 `MeshTraversalAttempt`，通过真实 HTTPS 驱动既有 native/Router。**正式 MeshRunner 的候选收集、全机准入和自动调度尚未接入，也未升级现用协调服务。**

## 控制面

- 能力声明作为 `MeshAnnouncement.Traversal` 放在现有加密、成员签名的公告内：控制版本、native ABI、BootId、支持的 profile。旧公告缺少该字段仍可读取；不能据缺少能力声明擅自启用新流程。
- 新 `POST /v3/mesh/{network}/traversal` 接受 `Offer / Ready / Start / Cancel / Selected` 的有类型状态。消息包含发送/接收成员及 Boot、Attempt、候选身份/版本/观察、协议角色、提名 revision、验证 nonce、顺序号、消息 ID 和有效期。
- 控制消息使用成员 ECDSA 签名并经现有 HTTPS 传输。它们没有业务字节数组、socket/Lease/Attach 句柄、密钥或回调 URL。候选地址不是对协调服务器加密的；服务器只保存这些控制元数据，业务仍 P2P。
- 每批最多 7 条、每个目标最多 1 条。先验证整个批次，再原子更新状态。签名、成员资格和目标均检查；网络 bearer 不足以冒充其他成员。
- 每个有向成员对最多保存两个 Boot 组合，支持重启交叠；全网最多 112 条当前状态。接收端每次最多 14 条，按接收成员及当前 Boot 过滤。消息最长 60 秒，防重放记录每网络最多 4096 项，访问时清理过期项。新的控制请求还以最多每 15 秒一次的频率清理所有网络，避免离线网络长期保留过期记录。
- 相同当前消息的 HTTP 重试幂等；曾经接受但已被较新消息替代的旧 Offer/Start 重放返回 409，不能回滚当前状态。接收端另保留自己的顺序、候选与终态校验，不把服务器内存当作最终授权。
- 复用每设备一条长轮询；控制消息只唤醒目标成员，不触发无关成员重新请求。控制事件不等待普通公告的 100ms 合并窗口。旧 bearer-only GET 不返回控制收件箱。
- watch 响应显式声明控制版本。客户端仅在版本协商成功后允许发送新消息；普通请求仍为 8 秒，watch 仍为 35 秒，watch 最大缓冲增至 128 KiB，普通 GET 仍为 64 KiB。
- 新消息共用每设备 48 次/分钟 + 8 burst、网络 512 次/分钟的请求预算，重复请求也计账。尚未完成产品侧优先级队列及 Ready/Start 的全机公平准入。

## Attempt 与实际资源

`MeshTraversalAttempt` 直接连接 `IPreparedMeshPath` 与 `MeshRouter`：

1. 较小成员编号发 Offer，避免同一成员对交叉申请。此规则只确定 SO 上层 client/nominator；两端 TCP 外形仍都主动发 SYN，与旧显式入口的方向选择无关。
2. 响应方在分配资源前验证 Offer 的签名、双方当前 Boot、能力及角色；本地资源 Armed 且上下文一致后才发布 Ready。
3. 发起方核对 Ready 中回显的完整本地候选，准备实际捕获后发 Start；响应方仅在自己的 Prepared 状态接受 Start。
4. 同一候选版本的地址、观察、角色或 nonce 不允许悄然改变。重复 Start 不重新分配或执行另一次激活，Cancel 后的迟到消息不能复活该轮。
5. 激活后由 Attempt 将实际路径引用注册进 Router。共同提名继续经候选数据路径完成，并沿用 native/UDP 的剩余期限。HTTPS `Selected` 仅用于状态协调，不能将路径晋升为 Active。
6. Attempt 结束不释放已转交 Router 的引用；显式 Cancel 是另一项操作。未转交、失败或取消的 Prepared 资源由 Attempt 负责清理。成员撤销后即使无法再发送 Cancel，也执行本地取消。
7. Active 状态报告可以包含已过候选公告期的历史观察，不能因此拆除活跃链路；同样的过期观察仍不能用于新 Start。

`NativeDatagramPath` 实现该准备接口；已退出或已处置的 native 不能再声称 Armed。Router 可显式使用协调客户端的 BootId，正式 MeshRunner 已统一这两个本地代次；它当前仍走原有承载调度，未发布新承载能力。

## 本轮验证

`tests/StreamLink.MeshTraversalTests` 的第一轮在一个负例预期处失败：测试将发送者改成接收者，首先触发形状校验 400，而断言要求身份校验 403。修改负例为另一个合法格式的设备 ID 后，验证了真正的签名/身份拒绝，未放宽实现。

`artifacts/mesh-traversal-https-native-20261011b.json`：**240 个检查、30/30 轮真实 HTTPS + 实际 C++ 协议通过**。

- HTTPS 使用临时内存证书及 pin，不安装根证书、不访问现用服务器。
- 候选和角色通过加密公告与签名 Offer/Ready/Start 实际交换，不直接把另一端的 Context 填给 Router。
- 实际 native Prepared、SO、HTTP/bare、认证包长探测、MeshLink、共同提名和双向 1280B 内层 IPv4 均参与。
- 首轮结束 Attempt 后额外等待 8.5 秒，证实 Active 不随原建链窗口结束；随后继续双向业务。
- 覆盖旧 Boot、候选篡改、重复/迟到 Start、过期控制与观察、未 Armed 的 Ready、批次原子性、重放、定向唤醒、撤销和旧 API 隔离。
- raw 收发是测试专用回环通道，IP adapter 为内存实现。**这不是 WinDivert/WAN/真实 NAT 或正式 MeshRunner 自动启动验收。** 上一提交的两 Windows WinDivert 证据仍单独保留，未混为本轮 HTTPS 真机证据。

新检查加入统一 Local 验证入口，步骤由 14 增至 15。

统一回归首跑 `artifacts/validation-control-20261011/manifest.json` 为 Fail：native Router 的测试 UDP 通道绑定返回 Winsock 10048，发生在 Armed 之前，而非 TCP/HTTP 握手失败。原夹具先用临时 socket 选端口再关闭，该端口在 native 启动前可能被后续 bridge 重用。

修复只作用于 `UDP2RAW_TEST_IO` 编译分支及其夹具：测试 native 自己独占绑定端口 0，并向回环代理发送带本轮随机 token 的 `SLT1` 注册，代理学习实际源端口；不再先释放原始收发通道的预选端口。注册不计入原始 IP/TCP 包统计；正式 WinDivert 分支没有这个通道。准备后放弃的 server 显式清除夹具登记，再接受新 attachment。没有用忽略绑定错误或自动反复重跑来掩盖该失败。

修复后 `artifacts/validation-control-20261011b/manifest.json`：**15 项全部通过**，包括 native Router 455 检查/30 轮、HTTPS 控制 240 检查/30 轮、UDP 接入 90 轮及既有连接/协议回归。

随后增加 `UdpTraversal.PreparePath`，将同 socket 的准备资源接到相同 Attempt 接口。激活返回独立 retained path；Attempt 结束释放准备 owner，Router 仍持有获胜 socket，Router 关闭后最后引用释放。`artifacts/mesh-traversal-prepared-udp-20261011.json`：**243 检查、30/30 HTTPS/native 轮通过**，新增真实 UDP/socket/Router 生命周期与业务检查。此补测发生在上述统一回归之后，不混入该 manifest。

补正 UTC 时钟裕量：新控制发布有效期为 55 秒、接收上限仍 60 秒；watch 发布 40 秒、上限仍 45 秒，允许两端约 5 秒偏差。候选观察同样限制未来最多 5 秒，过期仍拒绝；本机 8 秒/6 秒单调轮次期限不变。`mesh-traversal-clock-20261011.json` 34 检查及 `mesh-watch-clock-20261011.json` 25 检查通过，包含时钟偏差、实际 UDP 生命周期和真实 HTTPS 长轮询。

## 下一步与回退

还需将端点收集器、native 能力预检、TCP/UDP 全机资源、出站控制队列、阶段超时/失败码和上述 Attempt 接入 MeshRunner；保留显式 P→Q 快速路径，处理新旧资源管理互斥及失败回退。共享 native broker、严格 NAT 增强与 M5—M9 工作项保持原目标。

当前现用客户端/协调服务均未部署更新，默认承载不变。新服务路由向后兼容旧 GET/watch 与旧公告；未持久化协商消息。撤销本次提交即可回退开发改动，不需要恢复网络配置。
