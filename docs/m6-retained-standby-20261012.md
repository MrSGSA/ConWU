# M6：正式流程中的独立备用路径

基线：`b2c5eb3`。这是下一版源码进展，已发布的 `v0.5.3-preview` 不包含本次改动；没有更新已安装服务或公网协调服务。整体 M0—M9 目标继续，发布 Gate 没有通过。

## 已实现和正式接入

`MeshRunner → MeshTraversalManager → MeshCandidateFactory → MeshTraversalAttempt → MeshRouter` 现在可以在已有健康受管路径时，收集、认证并保留一个独立备用。设置、后台 IPC、成员签名公告和协调 HTTPS watch 都有独立的 `StandbyPaths` 能力；设备默认关闭，需要双方和协调服务支持。兼容入口没有该能力，旧设备/旧协调能力不触发备用资源分配。

备用只使用普通 FakeTCP SO 或 UDP_DIRECT 候选，不使用预测、来源学习、多 socket 探索或网关回退。TCP 工厂使用真实成员 ID 对应的备用源分区；观察和 native 接入仍共享该分区的持有资源，不在原 Active 四元组上再启动一套 SEQ/ACK。UDP 保留从 STUN 到认证的同一个获胜 socket，接收者和路径引用保持不变。

原 SLN1 提名行为保留。新 SLN2 仅用于双方明确授权的备用上下文，绑定候选身份、启动代次、修订及验证随机数。先在原有 TCP 8 秒或 UDP 6 秒剩余期限内完成双向认证和 MTU 检查；随后互认 Ready，进入固定最多 120 秒的保留阶段。重复保活不续期，不重新发起 TCP 握手。后续双方本地批准后才执行一次独立的 8 秒共同提名窗口；HTTPS 的 Standby/Selected 消息仅用于对账，不能提升路径。

原路径继续承载业务。native 备用的实际注入走既有维护账本，Business 标签不能绕过准入；普通 UDP 备用控制也使用全机维护预算。全机最多准备/持有一个后台备用，准备仍占现有轻/重建链名额，持有的 socket/端点仍占原资源额度。后台开始前要求 Active 驻留 30 秒，启动/结束后至少 60 秒冷却，前台建链优先。所有这些时间是本轮工程初值，不是公网成功率承诺。

原生期限已过而保留授权失败时，只取消备用，不让异常传播成整个 Runner 失败。取消/进程退出收敛后恢复管理原 Active 的 actor；共同提名后的取消仍可在旧资源保留期内回退。后台准备也不会改写普通 UDP 网关轮次的状态。

`MeshPeerStatus.Standby` 给出本地资源 ID、路径 ID、协议、双向新鲜度及剩余保留时间。其质量始终标记 `QualityUnknown`。内部选择接口继续受 `PreferFakeTcp` 保护，健康 FakeTCP 不允许被 UDP 备用抢占。

## 本轮实际证据

| 产物（均在仓库本地 artifacts） | 实际覆盖 |
|---|---|
| `m6-standby-router-final-20261012.json` | 978 检查：210 轮控制状态模型（每种机制30轮），一次真实 UDP 回环 Router/MeshLink；保留、双方批准、后续提名、回退、注入授权拒绝隔离及引用回收。 |
| `m6-standby-runner-refined-20261012.json` | 29 检查：真实 C++ 协议测试组件、独占 TCP helper、认证管道、HTTPS 和正式 Factory/Runner；raw IP/网卡为内存模型。正常双端备用超过8秒仍仅维护；主动终止备用后原业务继续；旧 peer/server 能力负例不分配第二个 helper。 |
| `m6-standby-udp-runner-20261012.json` | 9 检查：正式 Factory/Runner、真实 IPv6 UDP socket、HTTPS、完整1280B内层IPv4；备用同一资源持续保留，取消后原 Active 继续；内层网卡为内存实现。 |
| `m6-standby-pool-20261012.json` | 43 检查：真实 Windows TCP helper、唯一捕获所有者模型；七 peer 共用源、备用独立源、同一 peer 的备用观察合并、取消和关闭隔离。未启动 native worker。 |
| `m6-standby-signatures-20261012.json` | 128 检查：签名形状、独立能力、默认关闭、server/peer权限缺失、候选目的不可混换、普通流程兼容。 |
| `m6-standby-released-core-20261012.json` | 134检查（含6项真实旧库检查）：加载已发布0.5.3包的Core DLL，在独立程序集上下文使用旧解析、AES-GCM、签名和普通Offer验签；新旧公告互读及未知能力不授权。不是旧服务进程/旧网络端到端测试。 |
| `m6-standby-watch-20261012.json` | 42 检查：真实固定证书 HTTPS、独立备用能力与旧服务器回退清理；八隔离成员不是八真实终端。 |
| `m6-standby-windows-20261012.log` | 87 Windows前台生命周期/DPAPI/设置/IPC/忙碌反馈检查；没有改变在用服务。 |
| `m6-standby-legacy-nomination-20261012.json` | 270轮旧SLN1认证控制模型、52126断言；不能当公网或实际驱动覆盖。 |
| `m6-standby-legacy-router-20261012.json` | 222受管Router回归；撤销、同路径往返、无成员中继、引用回收。 |
| `m6-standby-native-regression-20261012.json` | 三节点受控原生回归，两个方向各20秒，聚合约49.961/49.962Mbps、最终统计损失0。真实C++/管道，raw IP/网卡为内存；不是WAN、运营商QoS或实时送达证明。 |
| `m6-standby-final-app-build-20261012.log` | 最后源代码的App/Service/Core Release构建零警告、零错误。 |

正式 native 测试在后续 status 字段/原生期限拒绝隔离补丁之前执行；UDP正式测试在期限拒绝隔离补丁之后执行。978检查的最终Router测试覆盖该隔离补丁。最后审批接口策略检查和UDP备用跳过网关的变化由最终构建覆盖，已有回归中的普通合法选择与网关未启用正例仍有效，未声称实际网关备用已测试。代码没有修改C++ HTTP/SEQ数据profile。

保留失败记录：首次App构建使用错误项目文件名；首次native实验误用生产组件，其拒绝回环端点后退出；边界测试起初错误要求两端同时产生原生期限失败，而对端可能先收到取消；一次构建与同一测试apphost运行冲突，随后等待原进程结束重新构建并通过。失败产物不删除、不作为成功证据。三份 `dotnet run` 输出原在各测试项目的 artifacts 中，已按原内容复制到仓库 artifacts，未重新生成结论。

旧库补测的DLL版本为0.5.3.0、SHA-256为`474130E8C8F3501F542E1FDF90658BAFFBF38F56DE2D662785332AB74EB24F38`，匹配该发布包构建收据。公告签名覆盖原始加密Data，因此旧解析器忽略解密后的新能力字段仍可验证端点公告；普通候选省略Standby默认字段，旧Offer验签也通过。新增备用消息仍需新能力，未让旧解析器接收SLN2。补测初次编译失败是空值抑制操作符与相等操作符之间缺空格，修正后构建和134检查通过；最后只改控制台“附加结果行”标签，避免把旧库反射测试误称为HTTPS/native轮次。

## 尚未完成和下一步

- 备用保留已进入正式流程，但**自动质量选择尚未启用**。`AutoQuality` 继续明确拒绝；不能从空载RTT、连通性或带1秒收尾的计数报告推导备用具备40–50Mbps串流质量。
- 下一步补入经过明确准入和预算约束的备用方向负载证据，将比较、驻留、迟滞、冷却和共同批准接入正式策略；保留健康FakeTCP及禁止业务重传/中继的约束。
- 本轮没有实际WinDivert/Wintun备用I/O、公网严格NAT新增覆盖、真实双端/八台Windows、休眠恢复、60分钟负载或跨协调失联验收。没有重打安装包，也没有为本次新能力升级生产协调服务。
- 第一条网络冷启动、驱动、真实SO/NAT矩阵等既有Gate仍按总执行状态记录，不能用本轮局部测试替代。

## 复现和回退

从仓库根目录构建对应测试项目，然后用已编译DLL运行。参数传绝对路径，例如：

```powershell
$root = (Get-Location).Path
dotnet build tests/StreamLink.MeshRunnerTraversalTests -c Release
dotnet tests/StreamLink.MeshRunnerTraversalTests/bin/Release/net10.0-windows/StreamLink.MeshRunnerTraversalTests.dll --native "$root/out/native/udp2raw-protocol-test.exe" --rounds 1 --output "$root/artifacts/standby-native-new.json" --standby-only
dotnet tests/StreamLink.MeshRunnerTraversalTests/bin/Release/net10.0-windows/StreamLink.MeshRunnerTraversalTests.dll --native "$root/out/native/udp2raw-protocol-test.exe" --rounds 1 --output "$root/artifacts/standby-udp-new.json" --udp-standby-only
dotnet build tests/StreamLink.ManagedPathTests -c Release
dotnet tests/StreamLink.ManagedPathTests/bin/Release/net10.0/StreamLink.ManagedPathTests.dll --standby-only --output "$root/artifacts/standby-router-new.json"
```

Local和Package检查入口已加入三个备用测试。尚未重新运行整个Package；打包时仍必须使用生产WinDivert组件，协议测试程序不得混入安装包。

该功能默认关闭；回退可取消勾选“保留独立备用路径”并保存。保存会按既有流程重建该网络，因此在串流空闲时操作。旧配置无需迁移。当前两端现用0.3.2服务没有被替换，已发布0.5.3包也没有被覆盖；该局部源码仍可按提交回退，不涉及Lucky或无关网络配置。
