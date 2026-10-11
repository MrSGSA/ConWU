# M1/M3：兼容 TCP 入口的 P、Q 所有权

基线 `582a09b`。本次落实执行计划 §6.2：保留既有 TCP STUN P + UPnP P→Q 入口，把 P 的辅助连接接入现有 `TcpEndpointLease`，并明确 native Q 的独占绑定。没有改变 HTTP 前导、SEQ/ACK、外层加密或数据报语义。

## 实现与产品接入

- `TcpBinding` 持续持有唯一 Lease；固定源端口的观察和后续保活都使用它。`Pulse` 获取在途引用，串行执行 STUN 事务。释放 Binding 时，在途查询结束前不关闭端点；失败的 TCP 事务不能再次用于查询。
- 首选服务器及备用服务器筛选仍沿用原 12 秒轮次。临时端口只筛服务器，真正发布的观察必须来自固定 P。临时 TCP 查询也通过 Lease，和受管 native 源、兼容 helper 共用已有 **8 个 TCP 资源**上限；它不是 UDP 的 8 个资源池，也不代表所有原生监听端口已进入统一总账。
- 两个 C# 路径都移除 `ReuseAddress` 和 `Linger(true, 0)`。绑定冲突保留原始 Winsock 错误，并返回 `TcpEndpointBusyException / EndpointBusy`，不依靠强抢或复位来快速换持有者。
- `TcpBinding.Snapshot`、`TcpMapping.HelperResource` 及映射日志关联 Lease、代次、实际 local/reflector tuple。辅助查询健康和端点关闭状态分别记录。这些本地标识不进入公网公告。
- Windows native 兼容 FakeTCP 的端口预约明确设置 `SO_EXCLUSIVEADDRUSE`，覆盖服务器 Q 与非受管客户端源端口。已授权的 native attachment 仍跳过二次绑定。旧 raw UDP 的共享 helper 和组播接收用途没有套用这个修改。
- 正式 `MeshRunner` 与旧双机入口通过原 `TcpMapping` 调用直接使用这些改动。已选路径、独立网关租约及 helper 的故障处理仍遵循已有分离语义。

Windows 正常关闭后不保证该端口立即可重绑；因此保留端口忙的失败与后续退避，不承诺无等待交接。参见 [SO_EXCLUSIVEADDRUSE](https://learn.microsoft.com/en-us/windows/win32/winsock/so-exclusiveaddruse) 与 [closesocket](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-closesocket)。本次回环检查只证明测试条件下未显式复位 helper，不能证明异常退出或所有网络条件下都没有内核 RST。

## 验证证据

产物位于 `artifacts/`，提交和 SHA-256 收据为 `m1-legacy-port-ownership-receipt-20261012.json`。

| 产物 | 结果与范围 |
|---|---|
| `m1-legacy-lease-ownership-20261012.log` | **63 检查**。真实 Windows 回环 TCP、跨进程抢占、即时 EndpointBusy、同 Lease 并发保活、错误事务后停止查询、在途取消、正常 EOF、与原生源/临时筛选共用 TCP 配额；含既有路径替换、映射失效保留监听和撤销/退出回归 |
| `m1-legacy-shared-lease-lifecycle-20261012.json` | **30 轮、247 检查**。受影响共享 Lease 的真实 Windows 生命周期、在途引用、退役、同源观察与 8 槽资源回归；无 raw/驱动/公网 |
| `m1-legacy-port-after-20261012.json` | **11 个 C++ 协议回环用例**。新增分别抢占兼容客户端源与服务器 Q 的子进程，失败后原隧道继续发送；既有 HTTP/裸 UDP、丢失、乱序、重复、篡改与错误密钥回归通过 |
| `m1-legacy-mapping-regression-20261012.json` | **356 检查**。含正式 `TcpMapping` 的真实回环 helper 与 PCP 收发：查询失效保留独立 grant、通知变更保留原 helper、退出等待维护并释放资源；无真实路由器 |
| `m1-legacy-app-build-20261012.log`、`m1-legacy-native-build-20261012.log` | 核心/服务/界面 Release 构建零警告、零错误；两个 native 目标构建完成。`ctest` 中 SO 状态机 1/1 通过 |

HTTP profile：双角色均为 HTTP **180B**、bare **48B**，seq/ack 差值 **0**。客户端 flags 为 24/16，服务器 24/24；本轮间隔约 **45.09/46.20ms**。间隔是观测值，不是精确协议常量。

保留了修改 native 独占选项之前的 `m1-legacy-port-before-20261012.json`：本机旧二进制同样通过了抢占检查。因此这里没有宣称重现过 native 端口劫持漏洞；新选项将所有权要求明确落实到代码。与之不同，旧 C# helper 确实显式开启了端口复用与立即复位关闭，源码改动已移除它们。

## 未完成的 Gate 与回退

本轮协议测试使用真实 C++ 处理逻辑和回环 raw 适配器，**没有加载 WinDivert，没有真实 UPnP/NAT/Wintun 或公网 P→Q 成功证明**。线上 RST、受控 NAT 兼容与严格 NAT 成功率仍需独立验证；内核 ACK/SYN 线上开销统计、兼容原生实例总账、完整事件链也没有借此宣称完成。

现用服务、Lucky、网卡、防火墙和驱动未修改；安装包尚未刷新。所有权修复在新版兼容路径直接启用，不提供开启强制端口复用的开关。源码回退基线为 `582a09b`；若部署后遇到端口忙，应保留错误日志并恢复先前独立候选包，而不是恢复全局端口抢占设置。
