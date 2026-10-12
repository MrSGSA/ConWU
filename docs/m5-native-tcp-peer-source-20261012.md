# M5：原生 TCP 来源端点学习机制

基线 `97f7e13`。父进程 `TcpCaptureOwner` 和 C++ SO 都只按公告的精确端口接收。严格端向对端发送时若获得不同于 STUN 的源端口，即使另一端过滤允许第一包抵达，原实现也会在本机丢弃。

## 已实现的机制

- 只在显式授权的 brokered IPv4 SO 中启用。私有 Attach 描述符字节 94 表达新能力，必须同时具备 SO、统一捕获和线上预算；字节 95 仍保留为零。旧描述符保持原行为，IPv6 与预测端口窗口不使用该机制。`--native-info` 独立声明 `tcpPeerReflexive=1`，不改变公共 SYN/HTTP/data 字节。
- 父进程从本轮实际发出的 SYN 记录 ISS；在原八秒窗口内，最多接受四个来自已声明对端 IP 的初始无载荷 SYN/SYN+ACK 假设。SYN+ACK 必须确认本轮 ISS；错误 IP、错误 ACK、RST、纯 ACK、带载荷 SYN、自身及 helper tuple 不进入集合。
- C++ 仅在 `syn_sent` 阶段选择第一条可用变化来源；保持原 ISS，使用收到的对端 IRS 完成同一 SO 状态，随后继续原 HTTP/bare/udp2raw 数据 profile。IP 始终固定，不能在已建立/已认证期间继续换源。
- 父进程确认该回复对应本轮 ISS 与实际见到的对端 SYN 后，预留新 tuple。原公告 tuple 也保留到原生进程确认退出，两者只有一套握手状态；不能在旧 tuple 启动第二个独立 ISS。
- 来源学习只产生暂定端点。原有每 Attempt/成员上下文派生的外层密钥、1344B HMAC 往返、MeshLink 和共同提名仍全部必须通过。错误密钥和超时结果不会进入 Router。
- 合格路径 `Identity.ActualRemote` 与诊断报告真实选定端点；`PeerSource` 区分 Enabled/Hypotheses/Learned/Frozen，学习到来源不等同于认证或质量通过。每个捕获所有者对同一 IP 只允许一个来源学习者，避免将无法从 SYN 识别的两个成员混合。

原八秒截止、120 包/64KiB、全机控制预算、helper 双向排除、资源引用与无业务重传语义保持。一个合法首包必须先经过 NAT 到达本机；严格过滤阻断首包、TCP 状态机阻断或对端换到未声明公网 IP 时，本机制仍不能恢复路径。

## 验证

| 本机证据 | 实际覆盖 |
|---|---|
| `artifacts/m5-tcp-prflx-30-20261012.json/.log` | 793 检查。稳定端分别承担 udp2raw client/server，各 30 轮，60/60 认证与提名正例；关闭学习及错误密钥各一轮负例。 |
| `artifacts/m5-tcp-prflx-boundaries-20261012.json/.log` | 38 检查，包括 11 项来源边界和原 27 项端点池检查；实际父捕获循环，错误来源/flags/ACK/载荷、四假设上限、32 位回绕、非法 wire category 不改 tuple、冻结与别名退役。 |
| `artifacts/m5-tcp-prflx-baseline-20261012.json/.log` | 原正式 Runner 基线 92 项；三个实例共享捕获、完整 MeshLink 双向业务、原 UDP/FakeTCP 生命周期、退出一员后其他直接路径存活。 |
| `artifacts/m5-tcp-prflx-protocol-regression-20261012.log` | 11 个既有公开 profile/密钥/UDP 行为协议用例。 |
| `artifacts/m5-tcp-prflx-final-smoke-20261012.json/.log` | 最终诊断、常量和深拷贝调整后的各角色一轮及两负例；不把该次结果增加到上述 30 轮分母。 |
| `artifacts/m5-tcp-prflx-native-build-20261012.log` 与 `m5-tcp-prflx-app-build-20261012.log` | 生产/协议原生构建、App/Core/Service Release 构建通过；C# 零警告、零错误。验证与打包脚本语法通过。 |

正例从准备资源到 Router 提名及双向完整报文约 1.451–2.578 秒，平均 2.029 秒，仅为该受控拓扑耗时，无旧版本性能对照。关闭学习的同拓扑未认证，证明成功需要实际来源学习，而非碰巧打到了 STUN 端口。

夹具的稳定端为 EIM+ADF，先向严格端 IP 发包预热地址过滤；严格端按目的端点分别保存映射和过滤状态，helper 与对等目的得到不同源端口。原生 C++、真实 TCP helper、私有管道、UDP 回环桥、Router/MeshLink 均为实际执行；原始收发、NAT、内层 IP 适配器为内存夹具，且不模拟所有中间设备 TCP 序号/窗口检查。没有物理 WinDivert/Wintun、线上 RST 或公网成功率证明。

## 正式接入仍待完成

此提交是可调用的原生/父进程机制，**还没有生产配置、双方签名 capability/候选授权或正式候选工厂启用入口**。目前产品默认不会调用新选项。下一步需要：

1. 本地、对端和协调服务独立能力协商；旧组件缺能力时不能发送新授权位。
2. 正式候选与 Attempt 绑定来源 IP 范围；IPv6/预测窗口和未协商消息显式拒绝。
3. 对同一公网 IP 的多成员使用独立受管源或有界排队，不能让一个 wildcard 接收者猜测成员身份；资源仍按全机计账。
4. 正式 Runner 自动接线、故障/取消/旧版本负例，再推进可用的双 Windows 公网验证。

Local 增加 30 轮入口，Package 增加一轮机制检查。本次源码未重新打包/部署，`843dfbd` 的 0.5.1 候选及 Akane 原服务保持此前记录；完整 M0—M9 目标继续执行。
