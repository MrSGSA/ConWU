# M5：TCP 来源端点学习正式接入

基于 `83992c8` 的原生/父捕获机制，本次接入配置、签名协商、候选工厂与正式 MeshRunner。现用服务和 `843dfbd` 的 0.5.1 安装候选没有替换。

## 行为与准入

- 设备配置 `TcpPeerReflexive` 默认关闭。仅实验 TCP 打洞与 FakeTCP 网络可启用；设置页按后台独立能力展示开关，退回兼容打洞时清除开关。
- native 必须独立声明 `tcpPeerReflexive=1`，同时提供 IPv4 SO、统一捕获和线上控制报文计账。前台/后台 IPC 独立传递版本，不能只看软件版本号。
- 协调快照、双方成员签名能力、候选签名中的 `PeerReflexive` 分别协商。三方条件缺失时不产生学习候选；后续合法签名 Ready 也不能给未协商轮次扩大接收范围。旧组件省略新增字段，普通签名字节不变。
- `GatherSourceAware` 将授权接入正式候选工厂和 Manager。IPv6、UDP、预测窗口与该 IPv4 来源学习权限不能组合；不支持的请求在 DNS、helper 和捕获分配前拒绝。
- 保留原八秒握手期限、最多四个来源假设、同一公告 IP、ISS/ACK 校验、外层密钥、1344B 路径认证及共同提名。学习到来源仍不是认证成功，只有认证完成的实际 tuple 才能进入业务路径。
- 来源学习按已认证的成员设备 ID 分区持有 TCP helper/捕获所有者。同公网 IP 的多个成员使用不同本地源端点；同一成员可复用其两秒内真实观察，但不刷新观察时间。普通未启用模式继续共享同源资源。
- TCP 配额仍为全机八个，七个邻居的来源隔离不增加配额。预测准备可回收无人引用、没有原生 worker 的闲置来源；正在借用、正在查询、Active 或退役引用仍然占额度且不被强制关闭。
- helper 查询失效立即退役该查询入口，合法原生路径引用继续持有原源和捕获；替代查询使用新资源，不关闭重绑 Active 的端点。源池回收后重新获取产生新 Lease，不能复活退役资源。

## 验证与证据

| 产物 | 结果与实际范围 |
|---|---|
| `artifacts/m5-source-product-final-20261012.json/.log` | 28 检查。真实 HTTPS、TCP helper、C++、正式工厂/Manager/Actor/Runner。稳定端分别承担 client/server；三实例同公网 IP 的两条直接链路及部分连通；缺对端、服务或原生能力负例；七个成员源分区与分配前拒绝。 |
| `artifacts/m5-source-product-signatures-20261012.json/.log` | 80 检查，包括双方签名权限、后续消息不能越权、普通字段省略兼容、IPv6/UDP/预测互斥与默认关闭。 |
| `artifacts/m5-source-product-watch-20261012.json/.log` | 36 检查，真实回环 HTTPS 长轮询、独立来源学习能力、旧服务回退清除权限，以及已有撤销/限额行为。 |
| `artifacts/m5-source-product-windows-20261012.log` | 71 检查，包括 IPC 能力、实验设置保存、兼容模式清除与旧后台禁用；使用隔离前端/安装副本测试。 |
| `artifacts/m5-source-product-pool-final-20261012.json/.log` | 41 检查。真实 Windows TCP helper；候选/native 引用阻止回收，闲置回收确实关闭源/捕获，重新获取新资源，失败查询、排队取消和关闭收敛；包含原来源边界检查。 |
| `artifacts/m5-source-product-baseline-20261012.json/.log` | 正式 Runner 基线 92 检查；原 UDP/FakeTCP 自动协商、共享源、多成员业务及协调中断后存活。最终闲置回收的新增断言由上行 pool-final 独立覆盖。 |
| `artifacts/m5-source-product-prediction-20261012.json/.log` | 正式预测回归 30 检查；受控新鲜源观察、完整原生业务，以及端口保留前提改变时拒绝。训练窗口为合格合成夹具，不是公网模型。 |
| `artifacts/m5-source-product-final-build-20261012.log` | App/Core/Service Release 构建零警告、零错误。Local/Package 脚本语法通过，并加入正式来源学习的受控回归入口。 |

两端正例从 Runner 启动至连通分别约 8.558 秒、6.538 秒；三实例两条直接路径约 16.295 秒，包含 HTTPS/候选准备/调度。没有旧版同条件对照，不据此宣称加速或成功率提高。原生机制各角色 30 轮证据见[上一机制记录](m5-native-tcp-peer-source-20261012.md)，不把此次断言加进该轮次数。

原始收发、NAT 映射/过滤、内层 IP 适配器和缺能力对象仍为受控夹具。稳定端为 EIM+ADF，严格端为目的相关映射/过滤；夹具没有模拟所有 TCP 状态/窗口检查。三实例不是三台真实 Windows，七源分配不是八台真机验收。尚无本次物理 WinDivert/Wintun、线上 RST 或公网成功率证明。

## 部署、回滚与后续

后续已补两台真实 Windows 的受控来源差异验证，两个协议角色各一轮通过，详见[真机记录](m5-tcp-peer-source-windows-20261012.md)。它不将上表本地集成结果改成公网证据。

Local/Package 受控回归已接线；本次未重新打包、安装或部署协调服务。公网服务器必须升级后才能声明该能力，现有旧服务不会被客户端猜测为支持。旧服务与旧 native 的正常路径保留。

真实试验须使用独立配置和捕获源，先确认 helper 双向流未被截走、线上没有非预期内核 RST，再验证同路径认证和正式虚拟网卡业务。首包被 NAT 丢弃时没有来源可学；不承诺任意严格 NAT 必通。

回退为关闭 `TcpPeerReflexive`，继续旧候选和既有显式入口。已发布候选包保持独立原始哈希，不能把此次工作树二进制写入旧包或旧来源收据。完整 M0—M9 目标、真实环境 Gate 与安装回滚验收继续进行。
