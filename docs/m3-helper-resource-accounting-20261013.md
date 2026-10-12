# TCP helper 与兼容资源账本

2026-10-13，沿用 M3/M8 的全机资源管理要求。现用 Windows 0.3.2 与公网协调服务未替换。

`TcpEndpointLease` 在实际独占绑定后、连接前登记同一个 ResourceId；固定入口、临时筛选、普通保留端点和单次查询分别记录。查询等待不触碰 TCP 字节流；取消等待保持 QueryUsable，实际事务失败只使该 helper 不可查询。最后引用释放才关闭 socket、退出观测线程并释放登记。公开原有 Open/Query 签名保留。

已安装且可访问的 WinDivert 可提供精确 helper 四元组的 NETWORK 层观测。句柄使用 SNIFF、RECV_ONLY、NO_INSTALL；没有发送接口，不截包、不安装驱动。只累计方向、IP 长度与 TCP 头标志，不保存载荷或密钥。组件或驱动缺失明确显示 Unavailable；首次连接后才开始观测明确显示 StartedAfterConnect，不补造早期报文。IPv6 带扩展头/分片等不能由当前解析器形成完整证据。

每个进程的 helper 事务准入初值为 4 次/秒、突发 2，队列最多 32、FIFO；观测到 helper 外出包达到原 60pps 界限时延后新连接/查询。不拦截内核 ACK、重传或关闭报文。这是查询准入与局部开销反馈，不保证所有控制报文的实际总和低于 60pps；native/兼容包级总账仍需继续接入。

`MeshTransport` 另登记原生进程及已知监听 Q，并关联映射的 helper P。客户端实际 raw 源端口尚未观察时保持未知。兼容配额明确为一个监听与七个成员各两个 Active/Candidate，共 15；与受管 TCP 源池 8 个分开表示。请求退役后 PID/启动时间仍显示进程存活或无法确认时继续占额；确认退出后释放。停止幂等。公开状态保留聚合数字，详细资源表留在本地运行状态，不塞入界面 64KiB 回复。

本轮验证：

| 验证 | 结果与范围 |
|---|---|
| helper 专项 | 60 项通过，含实际回环 STUN、已有 WinDivert 旁路观测、迟到观测、取消等待与实际部分事务、FIFO、兼容配额和独立无网络测试子进程退出 |
| 端口生命周期 | 30 轮、248 项通过；真实 Winsock 回环与冲突子进程，无公网/驱动承载。部分事务负例先确认反射端收到请求再取消 |
| 旧入口与 Runner | 71 项通过，回环/隔离夹具，未修改在用配置 |
| Windows/UI/IPC | 100 项通过；服务和界面 Release 构建无警告/错误 |

原始产物：`artifacts/m3-helper-windivert-third-20261013.json`、`m3-helper-endpoint-second-20261013.json`，旧入口与 Windows 日志为 `m3-helper-legacy-final-20261013.log`、`m3-windows-final-20261013.log`。首次端口负例因取消发生在准入等待阶段失败的日志保留，不能作为已实际发送的事务失败证据。

`CompleteWireAudit` 明确为 false。现有证据不覆盖兼容 raw 的逐包分类/源端点、NIC 物理出口总数、并发全部 native 与 kernel 控制包的总账，也不覆盖公网 NAT/八真实 Windows/正式安装恢复。真实 WinDivert helper 观测不是 native 对等流的线上 RST 验收。M0—M9 总 Gate 不提升。
