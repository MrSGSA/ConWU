# M2 原生双主动：状态机和协议阶段

**本阶段不是完整 PoC-2 或发布验收**。正式产品协商、真机受控 SO、MeshLink 同路径认证和共同提名尚待接入/验证。现用服务未升级。

## 实现

`native_so_state.h` 实现每次 Attempt 固定 ISS、对端 IRS、交叉 SYN/SYN+ACK/ACK、幂等重复、序号回绕、取消、错误 ACK/旧 SYN、状态相关 RST 和有界重试。一个实例只执行一次 Start，不在原地替换已有有效四元组的握手。

`native_so.cpp` 接入真实 C++ client/server 事件循环与 raw 收包。两端均先发 bare SYN，完成 TCP 外形后按原来的 udp2raw client/server 角色进入 HTTP/bare/加密数据阶段。未改变 HTTP 的重叠序号、seq-mode 3、数据报丢失/乱序语义。数据阶段的 RST 交给既有 profile 处理。

SO 由受管 attachment 的 profile=2 显式授权；profile=1 和现有未受管入口保持原行为。新能力未在 MeshRunner/GUI 默认启用。当前每 attachment 一个授权 peer，尚非多 peer broker。

native 从本地收到 Start 起使用 8 秒建立上限，保留同一次 ISS。正式控制器还需用该轮剩余时间完成 MeshLink 认证和共同提名，不能再给认证阶段一个新的完整窗口。当前 Local 测试不宣称已经实现这条完整共享截止链。

## 本轮证据

1. `artifacts/so-state-model-20261011.json`：630 个纯 C++ 模型用例。每机制 30 个确定性 ISS 样本，包括回绕；启动偏差 ±100/500ms，丢包、重复、逆序到达、取消和负例。不是 NAT 证据。
2. `artifacts/so-native-protocol-20261011.json`：初步 30 轮真实 C# 父进程 + native 子进程 + 同源 helper + 真实加密 UDP echo，通过。
3. `artifacts/so-native-matrix-20261011b.json`：180 轮、1891 条检查。六组各 30 轮：正常、首个 SYN 丢失、首个 SYN+ACK 丢失、首个纯 ACK 丢失、server 先启动 500ms、client 先启动 500ms。丢包方向在组内交替；每个故障必须在报文记录中确认实际注入，不能仅凭配置算覆盖。
4. 六组均要求双方实际发出 bare SYN、完成原有 udp2raw 加密通信，并从有界头部记录确认双方 HTTP(180B)/bare(48B) 的 seq/ack 重叠保持。完成后结束 Attempt/owner，继续通过保留引用查询 helper；撤销释放；最后一轮覆盖 worker 被杀。
5. `artifacts/protocol-after-so-20261011.json`：原 10 项协议回归全部通过。

所有 native 协议试验使用独立 `udp2raw-protocol-test.exe`，raw IP/TCP 报文经**回环 UDP 测试承载**传送，未加载 WinDivert。记录的是实际 C++ 协议和事件循环行为，不是纯状态模拟，也不是公网/真机 SO 成功率。

矩阵的测试代理在两个 native raw 测试 socket 就绪前暂存首批报文；启动偏差包括此人为延迟，不能宣称已经覆盖所有真实初始过滤窗口。`elapsedMs` 包含每轮资源/进程准备与清理，不是规范定义的双方 Ready 后建链耗时。

## 保留的失败与修正

- 初次 SO 回环出现测试 UDP carriage 在另一端未 bind 前收到 ICMP port-unreachable，触发 Windows 10054。仅在 `UDP2RAW_TEST_IO` 分支把该 ICMP 视为测试报文丢失；生产 WinDivert 错误处理未放宽。
- 第一版故障代理未等到双方 socket 就绪，特定方向没有出现要丢弃的 SYN+ACK。测试在第 62 轮拒绝以未实际注入的故障算通过；修正代理就绪时机后重新执行完整 180 轮。首轮日志仍在 `artifacts/so-native-matrix-20261011-logs`，最终证据为带 b 后缀的产物。

## 后续依赖

- 完成 M1 的受控/公网 Gate 和多 peer 所有权；产品启用 SO 前不得跳过。
- 父控制器提供分开的 Prepare/Ready 与 Start；跨成员协商绑定 BootId、候选版本、Attempt、角色、提名修订；路径认证共用剩余截止时间。
- 加入真实 Windows/WinDivert、受控允许/拒绝 SO 的拓扑、50Mbps 短回归及 Wintun/MeshLink 业务证据。
- M3—M9 继续执行；本报告不是整个版本完成声明。
