# M5：受预算约束的原生 TCP 端口窗口

基于 `ecfabae` 的独立校准继续实现原生承载适配。新增 `NativePortWindow`，可以在一个受管源端点上准备多个已授权远端端口，保留可验证的获胜原生路径。**这不是完整预测策略，正式 MeshRunner 尚未自动发布或接收预测端口窗口。**

## 原生接线

- 一个窗口仅包含一个 IPv4 地址、1—8 个不同端口；先复制并验证输入，再创建原生 worker。不同地址、重复端口、过大窗口不创建资源。
- 继续使用现有 `TcpCaptureOwner`、独占 helper 与 C++ FakeTCP＋HTTP 实现。每个目标 tuple 一套原生握手状态，不创建第二个 capture owner，不再次 bind 源端口。与现存 tuple 冲突时回收本次已经准备的子进程，保留原会话。
- 每个 worker 使用独立的原生 IPC 和 tuple；`NativeAttemptGroup` 为整个窗口共用一个 `TraversalControlRound` 和首次启动后的 8 秒期限。120 包/64KiB 是窗口总额，普通搜索仍预留24包供完成阶段使用。全机速率限制仍在实际注入边界执行。
- 最多八个 worker 有界并行准备，保留捕获先于 SYN 的顺序。任一准备失败会取消同窗其他准备，等待所有任务结束并回收那些恰好完成的子进程。
- 首个取得控制预算、即将注入的报文才调用一次领取预测的委托。Prepare、排队和 Start 本身不会消费预测。拒绝后该窗口不能发送首个 SYN，也不能通过 Select 绕过领取。生产调用者还须把这个委托绑定到 `NatPortPrediction.TryClaim`；当前测试使用受控许可。
- 双向原生载荷认证成功后选择获胜路径。先确认其他 worker 退出并释放 tuple，再向 Router 移交获胜路径；共同提名继续在该路径上执行。
- 移交后，结束窗口所有者不关闭 Router 持有的获胜路径。Router 得到的是原 `NativeDatagramPath`，继续使用共用控制账本和原 MeshLink 加密/重放状态；没有新增业务重传或成员转发。
- 无对端仍按共享期限退出；已确定的预测拒绝或领取异常通过异步信号立即取消，无需等八秒。失败资源回收后，原 helper 仍可查询。

单个获胜 worker 的 `WireControl` 仅包含它自己的实际报文；窗口总控制消耗查看共享 `ControlRound`，各失败 worker 的明细保留在窗口 Diagnostics。失败许可已取得但未实际注入的预算槽不回充，避免重试规避限额；不把它计为已经注入的握手包。

## 测试边界

验证使用真实 Windows 独占 TCP helper、实际 C++ 子进程、认证命名管道、MeshRouter、MeshLink。原始报文在内存路由器中投递，内层 IP 使用测试适配器。无 WinDivert/Wintun、公网 NAT 或签名协调协商，端口列表由测试直接授权。

正例分别测试协议 client 与 server 一侧使用端口窗口，另一侧使用一个固定端点。它验证原生端口选择与资源转移，**不证明真实网络的稳定映射前提，也不证明双端随机 NAT 可用。**

首轮在原生认证之后被 Router 正确拒绝：测试导入成员后未填入授权目录。修正测试准备并重跑，未放宽正式成员验证。

本机 `artifacts/` 记录：

| 产物 | 结果与范围 |
|---|---|
| `m5-native-window-final30-20261012.json/.log` | 最终并行版本746检查通过，三端口 client/server 侧各30/30；四类负例、原生进程退出、共同提名、真实加密内层包、HTTP/bare序号兼容全部核验。结束后系统中协议测试子进程计数为0。 |
| `m5-native-window-parallel-20261012.json/.log` | 50 检查通过。client/server 侧各一次八端口窗口，七个失败 worker 均退出；真实 Router 提名、完整1280B内层包双向通过；准备中冲突、重复/跨IP/过多端口拒绝、许可失效/异常、取消和无对端负例通过。 |
| 同上时序 | 八候选准备分别273ms、382ms；许可失效64ms退出且零注入，许可异常65ms退出且零注入，主动取消193ms，无对端8042ms。仅是本机受控样本，不是公网恢复目标。 |
| `m5-native-window-wire-regression-20261012.json/.log` | 72项既有实际注入计账、正式Runner/IPv6回归通过；这一回归使用最终快速拒绝和并行准备修正之前的版本，未使用窗口组件，后续改动不在其经过的分支。 |
| `m5-native-window-ipv6-regression-20261012.json/.log` | 23项通过，实际三个Windows TCP helper、C++子进程、共享capture与Router；IPv6 raw及内层IP受控。测试时间与上述回归相同，范围不是公网IPv6。 |

最初串行版本还有 `m5-native-window-30-20261012.json`，742检查、三端口 client/server 各30轮通过。发现明确拒绝仍等待八秒后已修正，且把八候选准备从随后单轮记录 `m5-native-window-final-20261012.json` 的1001/1088ms改成并行；旧产物保留用于说明时序变化，最终结果以上表为准。

复现入口：

```powershell
dotnet run --project tests/StreamLink.EndpointPoc -c Release -- --port-window <原生协议测试程序绝对路径> --rounds 30 --output <JSON绝对路径>
dotnet run --project tests/StreamLink.EndpointPoc -c Release -- --port-window-wide <原生协议测试程序绝对路径> --output <JSON绝对路径>
```

Local 验证新增三端口各30轮及八端口各1轮检查；打包回归新增八端口各1轮。两份PowerShell脚本语法解析通过，本轮没有重新运行整套Local或打包流程。源码改动未部署至现用服务，也尚未打入新的安装候选。

## 仍需接入

1. 双端签名能力/窗口交换与单稳定端前提；不能把一次 STUN 结果当作端点稳定证明。
2. 先保留源资源再同时测量新鲜锚点的协调阶段，避免普通 Offer/Ready 的准备耗时吃掉2秒有效期。整轮8秒还须包含约定的协调后各阶段，不能由新 worker 延长。
3. 正式工厂调用此适配器、传入实际预测领取与结果回报；两次真实失败停用、过期拒绝、网络代次失效及全机高成本准入。
4. 对预测规则和实际源端口变化进行受控 NAT 外侧核验，再做真实双 Windows 与公网 Gate。

现有默认单 tuple 路径不传入 group，保持原预算、期限及协议行为。该组件不自动启用预测，回退不需要修改用户正在运行的网络。
