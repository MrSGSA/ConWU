# M7：共享网关控制 socket 的单播通知与恢复

后续 IPv4 组播、Windows 共享端口与可回收额度已另行实现，见 [组播后续记录](m7-gateway-multicast-20261012.md)。以下保留本次单播提交的历史范围和证据。

基线 `50fb206`。现有 PCP/NAT-PMP Provider 在两次请求之间没有接收者，网关主动发送的映射更新只能等到后续续租时处理。本次增加持续的唯一接收循环及有界复核，接入已有 TCP 映射对象和 UDP socket 生命周期。**仅实现单播通知，组播监听仍待完成；无真实路由器、WinDivert 或 Wintun 验收。**

## 实现

- `PortControlChannel` 是共享、connected UDP 控制 socket 的唯一接收者。响应交给当前串行事务；其余数据报只分发给已经登记的租约。没有第二个读取同一 socket 的组件。
- 控制来源仍受 connected socket 的准确网关 IP:port 约束。PCP MAP 同时检查 nonce、协议、内部端口与结构；ANNOUNCE 校验操作、成功码、头部与选项边界。PCP/NAT-PMP 状态不会互相替代。
- 在空闲期处理 PCP MAP Update、PCP 单播 ANNOUNCE、NAT-PMP 单播地址/epoch 提示。普通 epoch 更新不触发重建。缺少单播通知的网关仍走原续租路径。
- 有效变化先将候选标为 `GatewayRevalidating`，唤醒同一租约的维护任务。继续使用原控制源端点、PCP nonce、内部端口和协议，保留原建议外部端点。
- 重启提示加入 0–5 秒抖动；每个租约复核起点至少间隔 5 秒。一个租约最多保留一个提示，重复报文合并。复核自身最多 8 秒，排队与协议重试都计入；失败标记 `GatewayRevalidationFailed`。
- 全部请求仍经过既有维护包预算、串行网关交换及全机 socket 配额。一个网关账户最多 32 个订阅，单报文不超过 1100B，无无限消息队列。没有新加通知 socket，因此七个 UDP 数据 socket 加一个控制 socket 仍占八个额度。
- 路由改变、接收器失效、取消和超时撤回候选。关闭一个租约不会关闭其他订阅的接收器；最后一个引用退出才取消并等待接收循环结束，随后释放 socket 和配额。
- PCP 清理仍限定精确 nonce/协议/内部端口；NAT-PMP 从不发送删除请求。通知不能赋予新的删除权限。

快照增加 `Notifications`（接受并合并的变化提示数）、`Revalidations` 和 `NotificationMode=UnicastOnly`。没有把收到的报文数量当成复核次数。现有 `PortControlMapping=false` 默认值不变，关闭时不会申请这些映射或启动控制接收器。

## 协议证据与限制

PCP MAP Update 与普通 MAP 响应在报文上相同，匹配 nonce 的重复更新可能满足正在等待的请求；不能宣称它提供了单独的事务新鲜度认证。这里证明的是匹配的受管映射资源。ANNOUNCE 的 epoch 与随机恢复等待、Mapping Update 的线格式依据 [RFC 6887 §14](https://www.rfc-editor.org/rfc/rfc6887.html#section-14)。NAT-PMP 地址通知及协议限制依据 [RFC 6886](https://www.rfc-editor.org/rfc/rfc6886.html#section-3.2)。

初次测试曾错误要求辨别“重复更新”与“新请求响应”，因此失败。失败日志保留在 `m7-notification-initial-20261012.log`；最终验收按相同线格式处理，没有把该能力写成已经具备。

新端点只是候选，仍须远端经过真实承载完成认证与路径检查。网关内层/CGN 地址不能作为公网入口发布。通知复核期间，已有业务不因元数据暂时失效而直接关闭；真实 NAT 状态变化是否中断业务，仍由实际链路健康判定。

## 本轮验证

产物位于 `artifacts/`，收据为 `m7-gateway-notification-receipt-20261012.json`。

| 产物 | 结果 / 覆盖 |
|---|---|
| `m7-notification-final-20261012.json`、同名日志 | Provider 284 检查，加原 UPnP 10 项共 **294**；新增错误来源/nonce/协议、畸形与正常 ANNOUNCE、重复合并、晚到旧租约、单订阅退出、共享配额、取消、路由失效及正式 TcpMapping 更新 |
| `m7-notification-bounded-20261012.json`、同名日志 | 最终 Provider **285** + UPnP 10，共 **295**；补充复核无响应负例，约 **8.012 秒**退出、包含初次建映射在内共 3 次请求；未降级或重发业务 |
| `m7-notification-runner-20261012.json` | **28 检查通过**；正式 UDP factory/Runner、PCP/NAT-PMP 后备候选、实际 UDP/STUN/HTTPS，内层 IP 适配器为内存实现 |
| `m7-notification-connections-20261012.log` | **46 检查通过**；TCP 入口重试、元数据失效保留监听、签名撤销和取消回归，受控本地接口 |

第一项包含真实 Windows 回环 UDP 控制收发和 TCP helper。一个 PCP 重启用例中，两项租约复核完成约 **5.02 秒**，普通续租下界为 90 秒；这是夹具的一次观测，不是用户路由器恢复保证。另一个 MAP 更新用例约 65ms 即恢复，其中匹配的重复 MAP 可以满足复核，不能称为测得了一次独立新事务的公网 RTT。

UDP 用例使用同一个获胜 socket 完成认证和 1344B 载荷检查，结束 Attempt 所有者后保留路径；随后暂停网关响应并发送重启提示。两端映射候选处于复核状态时，仍能顺序双向传送完整 1344B 载荷。复核完成后 `SocketResourceId` 不变，未删除仍被路径持有的映射；最终退出才清理。该子用例不使用真实网关转发，因此它证明生命周期分离，不能证明实际 NAT 重启必定不中断。

正式 `TcpMapping` 用例通过实际 helper + UDP 网关夹具验证：通知引起端口公告更新、helper 和 Lease 身份保留；后续通知返回 CGN 地址时拒绝发布。没有原生 FakeTCP 或物理网卡参与该子用例。

核心、服务、应用及受影响测试项目 Release 构建无警告/错误。复现时先在仓库设置独立输出路径，避免覆盖历史产物：

```powershell
$env:STREAMLINK_MAPPING_REPORT=Join-Path (Get-Location) 'artifacts/notifications-new.json'
dotnet run --project tests/StreamLink.MappingTests -c Release
dotnet run --project tests/StreamLink.MeshRunnerTraversalTests -c Release -- --native (Join-Path (Get-Location) 'out/native/udp2raw-protocol-test.exe') --rounds 1 --output (Join-Path (Get-Location) 'artifacts/gateway-runner-new.json') --gateway-only
```

## 剩余事项与回退

M7 仍未完成：224.0.0.1:5350 / IPv6 组播监听、按实际接口验证来源与多应用共享端口、独立于 STUN 的入口收集、真实网关和真实 IPv6 全链路 Gate 均待推进。当前未申请 5350 端口，也未添加防火墙规则，不能把单播实现描述成完整 RFC 重启通知支持。

回退可关闭原有 PCP/NAT-PMP 实验选项并重新启动该网络，保留旧 TCP STUN + UPnP 路线。代码基线为 `50fb206`。现用 StreamLink、Lucky、驱动、网卡和已有安装候选均未替换；此次仍是下一版开发提交，不是正式发布。
