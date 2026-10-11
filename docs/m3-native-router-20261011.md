# M3 原生承载接入受管 Router

本次在 `a608d1e` 的资源引用与共同提名基础上，实现 `NativeDatagramPath`，并完成本地实际 C++ 协议和两台 Windows WinDivert 验证。仍未完成正式 MeshRunner 自动候选协商，也不代表下一版已达到发布条件。

## 实现与资源契约

- `Prepare` 先绑定一个独占回环 UDP bridge，再通过 `NativeAttachment` 授权 native 使用持续持有的 TCP Lease；native 不再次 bind 源端口 P。捕获 Armed 后等待 Start。
- `NativeAttachment.RemainingRound` 从首次 Start 请求发送前开始计时。重复 Start 不刷新时钟；native、认证包长检查、MeshLink 和共同提名均消费同一轮 8 秒剩余时间。
- 外层密钥由成员 ECDH 共享密钥、本轮规范上下文及独立 HKDF 域派生；没有增加新的外层重传或字节流。原 HTTP、seq-mode 3、bare 和加密封装行为保持不变。此受管 profile 必须由新版双方明确协商，不能与旧共享密钥入口混用。
- `SLF1` 探测使用另一个 HKDF 域及 HMAC-SHA256，绑定双方设备/Boot、候选版本、角色、Attempt 和验证 nonce。检查与回复均为 1344 字节，回复须回显随机挑战。双方各自通过往返检查后才交给 Router。
- native server 的回环 UDP 源端口由其会话动态分配，bridge 仅在认证探测有效后固定该来源。client 则固定 native 的回环监听地址；其他来源无法抢占。
- 每个 bridge 只有一个底层接收者；探测与 MeshLink 分流。发送与接收各有 128 个数据报的有界队列，业务不重传。瞬态发送压力丢当前包，不因此销毁健康路径。
- `IMeshDatagramPath.Identity` 在认证/包长检查前不可用。实际源端点、远端授权 tuple、LeaseId、AttachId、NetworkGeneration 与 Attempt 一起交给 Router。
- 结束 Attempt/owner 不关闭 native 持有的资源。取消先停收发，退出 native 并确认子进程结束后释放其 Lease 引用。子进程退出事件立即使路径 Failed，Router 无需等待 12 秒链路存活窗口。
- bridge 的控制包与 Router 提名共用 `TraversalControlRound`，不另领一轮预算。native SYN/ACK/保活和完整外层开销尚未统一计账。

## 验证证据

### 本地实际协议

命令：

```powershell
dotnet run --project tests/StreamLink.EndpointPoc -c Release -- `
  --native-router out/native/udp2raw-protocol-test.exe `
  --output D:/Codex_workspace/UDP2RAW/product/artifacts/native-router-20261011.json
```

30/30 轮，455 个检查通过。真实子进程 IPC、C++ SO/HTTP、bridge、MeshLink、Router 参与；raw 包通过测试专用回环 UDP 通道收发，IP 适配器为内存实现，不加载 WinDivert。

覆盖：准备期无 SYN；未认证资源拒绝注册；伪造回环来源无法固定 server bridge；重复 Start 不延长期限；Attempt 结束后继续提名和双向完整 MTU 业务；两角色实际发 SYN；两角色 HTTP/bare seq/ack 重叠保持；分别丢一个 SYN/SYN+ACK/ACK；最后一轮 native 崩溃立即撤销路径；所有路径关闭后 helper 引用与临时配置回收。

该测试已加入统一 `Invoke-TraversalValidation.ps1`，Local 步骤由 13 增至 14。

最终统一验证 `artifacts/validation-native-router-20261011/manifest.json` 为 **14/14 Pass**，包含旧协议、watch、提名模型、既有连接/mesh、受管 Router、UDP 基础及 90 轮实际 Router 的 UDP 测试。其 sourceCommit 是 `a608d1e`，dirty=true（当前改动尚未提交时构建），没有把历史结果复制为本轮结果。

### 两台真实 Windows

测试节点：Thinkbook `10.129.129.2`、Akane `10.129.129.1`，**经过现用 StreamLink 虚拟接口**。独立测试程序、TCP helper、控制连接及源端口；没有替换或停止现用服务。

每端 30/30 轮、270 个检查通过。每轮重新建立真实端点及 native 进程，依次完成 helper 反射、Armed/Ready、交叉 SYN、HTTP/udp2raw、1344B 探测、MeshLink、共同提名、双向各 10 个 1280B 内层 IPv4 包、清理。

| 结果 | Thinkbook | Akane |
|---|---:|---:|
| Start → 提名完成 p50 | 1446 ms | 1376 ms |
| p95（30 样本最近秩） | 1467 ms | 1439 ms |
| 最大值 | 1477 ms | 1473 ms |
| 有效收发窗口内 RST | 0 | 0 |
| 捕获错误 | 0 | 0 |

使用各端单调时钟，计时包含本轮 native、认证包长检查、helper 再查询、MeshLink 和提名，不包含部署、控制连接建立、候选准备或虚拟网卡创建。因此不可宣传为完整软件开机恢复耗时。

接收侧 WinDivert NETWORK/SNIFF priority 200 观察包，native 独占捕获 priority 100。抓包证明对端 Windows IP 层的到达情况，不是物理出口 tap。无非预期 RST 不代表已经覆盖所有 TCP 状态设备。

本机记录到的最大外层 IPv4 包为 1446 字节；记录尚未包含 DF/分片字段，不能据此单独宣称完成 PMTU 验收。

产物均位于忽略目录 `artifacts/`：

- `native-router-two-windows-local-20261011.json`
- `native-router-two-windows-remote-20261011.json`
- `native-router-two-windows-provenance-20261011.json`

双方 native 与 harness 哈希核对一致。测试结束后两端剩余测试进程为 0、临时防火墙规则为 0；两端正在使用的原服务保持运行。远端文件保留在 `E:\Codex_Workspace\Streamlink\m3-native-router-20261011-a`，节点私密配置由测试脚本 finally 清理。

本地为部署复制的 `out/native-router-poc/remote-private.json` 副本清理被自动审批拒绝（仅返回 blocked by policy），暂留在 Git 忽略目录；未提交。它是独立临时网络凭据，不含现用网络凭据。

## 未完成与适用范围

- 两机数据链路通过旧组网接口，不能作为新公网 P2P 或校园网严格 NAT 成功证据。公开反射到新 WAN 承载连续性仍待验证。
- IP 适配器仍是内存实现；真实 Wintun 两机完整业务、50 Mbps 回归和 60 分钟稳定性未在本轮执行。
- 测试程序通过已认证、仅含控制消息的点对点 TCP 通道提供 Ready 与本轮身份；正式 HTTPS 协调 Offer/Ready/Start 和 MeshRunner 自动接线仍需完成。
- 当前一个 Lease 一个 native attachment，一个 attachment 一个精确 peer tuple。共享源端点的多 peer 捕获 broker、授权来源学习及 native 实际 tuple 上报尚未完成。
- 当前成功包长证明完整数据报能通过；尚未记录物理路径 DF/分片，不据此宣称 WAN PMTU 合格。
- native 的控制包预算、全机 TCP 资源池、严格 NAT 增强、pacing、最终状态重同步、八真实终端与安装/回滚验收仍按执行计划继续。

## 回退

本次没有修改现用配置、安装服务或启用新默认承载。正式 Runner 仍使用既有显式入口；受管 SO 仅由明确协商的调用者或独立测试触发。开发回退可撤销本次提交，不需要恢复系统网络设置。
