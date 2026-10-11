# M5：独立 TCP 端口校准收集器

在 `6b209a2` 基线上把校准接入正式 `MeshCandidateFactory`、Runner 状态和设置页。新增能力只收集与评估分配规律，**不发布预测候选，不改变现用选路；M5 尚未完成。**

## 实现与边界

设置中的 `TcpPortCalibration` 默认关闭，需要同时启用受管 TCP 与 TCP 观察。后台通过 `TcpCalibrationVersion=1` 宣告能力，旧后台下不可选。启用后只在目标 peer 没有连接时工作；其他成员健康连接不会阻止该目标的校准。普通候选继续建立，校准不阻塞 Gather。

每个窗口使用新的独占 TCP helper、本地源端点及唯一 capture owner。helper 在窗口内保持存活，原生 SYN 使用该源端点而不再次 bind。原有候选 helper 与捕获资源仍由原所有者管理。窗口结束立即释放额外资源，不占用端口等待下一窗口。源 tuple 重用、出口/观察目标变化、证据不完整均不能训练模型。

固定两个主要观察目标；干扰窗口在二者之间插入第三个目标。至少需要三个可用观察点，而现有目录每个 IP 最多两个端口，因此需要至少两个观察 IP。20 个新源窗口按时间前后各一半训练/留出，每三窗中的一窗包含额外探测；只拟合一次，留出失败不重新挑模型。

`ObservedBackgroundActivity` 表示**已观察到的附加 SYN 探测**。它不是已证实的 NAT 分配次数；真实网关可能复用映射。只有受控 NAT 测试的分配表才可计数。原 `ObservedBackgroundAllocations` 命名已更正；这是本地诊断结构，不改签名协议。

全进程多个候选工厂共用一个校准名额，排队期间不申请额外端点。仍受既有全机 TCP 资源、维护发包和协调请求预算约束。独立运行的第二个服务进程不共享该静态队列，生产仍依赖既有单服务/端点所有权约束。

- 正常窗口间隔至少 31 秒，**从登记回复到达开始计时**，避免网络延迟使两张票据/成员/60 秒的上限被突破。
- 整个收集任务上限 15 分钟；正常约 10 分钟。该时间包含排队与等待目标状态。
- 目标连接恢复时，正在观察或等待下一窗的任务均退出；未完成窗口不参与训练。恢复后重新收集至少冷却 90 秒，以覆盖在途签名请求和旧票据保留期。
- 工厂停止时等待校准任务退出、释放源和捕获，并使内存模型失效。校准报告不能作为重启后可用的预测授权。
- 本地报告 `tcp-port-calibration.json` 包含窗口、原始观察、评估、退出原因及 `candidateEnabled=false`；包含实际端点，按诊断数据处理，不加入源码包。

## 验证

本轮采用真实独占回环 TCP helper、正式工厂、Core SYN 构造及原资源预算。观察 API、原始收发和 NAT 分配为受控内存夹具；**不包含签名 HTTPS 观察服务、原生 worker、WinDivert、Wintun 或公网 NAT。**

20 窗案例为了测试时长将窗间隔置零，但仍等待每个八秒观察窗口结束。它没有模拟服务器票据保留上限，不能冒充十分钟真实在线校准。生产 31 秒间隔另有等待/释放/取消测试。

本机 `artifacts/` 下的产物不随源码提交：

| 产物 | 结果与范围 |
|---|---|
| `m5-calibration-lifecycle-final-20261012.json/.log` | 36 检查通过；正式工厂 20 窗收集及六类生命周期场景、多工厂排队。固定步长受控模型在 10 个留出窗命中 10 个，窗口宽度两端口；不代表公网覆盖。 |
| 同上 20 窗计数 | 20 个不同源资源、本地源 tuple，7 个附加探测窗；141 个原生 SYN、47 个夹具确认的目的映射、60 次观察 API 调用、21 条真实 helper 连接（原候选一条加校准20条）。结束仅保留原候选捕获。 |
| `m5-calibration-model-20261012.json/.log` | 58 检查通过；沿用模型/UDP 受控验证，新增观察顺序、完整来源身份、干扰未抵达及错误插入位置的拒绝。 |
| `m5-calibration-baseline-20261012.json/.log` | 68 检查通过；真实正式 Runner、HTTPS、socket/C++ 协议，端点与 IP 适配为回环/内存夹具。默认关闭时既有三 Runner 共享资源、受管 TCP/UDP 与业务生命周期通过。该回归在最终校准窗间取消修复之前执行；校准默认关闭，不经过修改分支。 |
| `m5-calibration-windows-20261012.log` | 58 检查通过；设置开关、旧后台兼容、依赖开关、配置及隔离前台生命周期。未操作现用服务和网络。 |
| `m5-calibration-settings-20261012.png` | 已检查设置页截图，新增开关与保存按钮可见，无遮挡。 |

关键复现入口（仓库根目录）：

```powershell
dotnet run --project tests/StreamLink.MeshRunnerTraversalTests -c Release -- --native <原生协议测试程序绝对路径> --rounds 1 --output <JSON绝对路径> --prediction-only
dotnet run --project tests/StreamLink.PredictionTests -c Release -- --output <JSON绝对路径>
dotnet run --project tests/StreamLink.WindowsTests -c Release
```

测试记录中的 `Pass` 指对应范围，不能替代 30 轮真实双 Windows、WinDivert、完整观察服务或公网校准 Gate。通用 I/O/观察失败当前归为 `PredictionNotSupported` 并保留异常原因，尚需细分基础设施失败码；该状态不证明 NAT 的分配数学上不可预测。

## 后续与回退

仍需把模型用于新鲜源锚点、双端认证候选与受预算限制的原生握手；不能向多个目标猜测后仍假设自己的 APDM 源映射不变。概率探索、真实 NAT/外侧抓包与发布 Gate 继续待完成。

目前可用服务器只有一个受控公网 IP，未取得所需完整观察拓扑；本轮未改线上服务器或两机网络配置。最新已打包候选仍是 `f648059`，不含此校准改动。

回退只需关闭 `TcpPortCalibration`，恢复原一次性 TCP 观察；关闭 `TcpSynObservation` 则同时关闭校准。当前未升级用户现用服务，无须修改其部署。
