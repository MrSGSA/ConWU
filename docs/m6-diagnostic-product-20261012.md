# M6：有界方向负载诊断正式接入

基线`ccf08aa`。本次把诊断能力、目标、共同控制、接收摘要、业务保护和资源回收接入正式Factory/Attempt/Router/Runner以及设置与IPC。整体M0—M9目标继续：自动质量判定/切换尚缺，`AutoQuality`仍明确拒绝；未重新打包或升级在用服务/公网协调服务。

## 最终行为

设备默认关闭PathDiagnostics，启用需独立备用、受管模式和不少于目标1.4倍的共享外层出口额度；目标1–50Mbps，默认50。成员签名公告独立声明版本及目标，双方和协调服务均授权且目标一致时，Attempt捕获该权限。普通路径、旧peer/server、目标不一致仅保留普通连接，不默许压测。

备用完成原有双向认证/MTU后，Router捕获原Active/备用的实际资源、启动代次及MeshLink方向epoch。双方交换SQD2共同准备/启动/结束/摘要/确认；控制体固定192B，目标、1280B样本、5秒窗口、90秒共同期限、256MiB共同字节与原候选验证scope绑定。每个方向按顺序测量原Active和备用各3个5秒窗口，全事务12个窗口；诊断发送比目标多5%，最终仍受共同pacing与IP准入控制。数据不写入内层网卡、不重传。

维护控制复用现有公平调度及维护账本，最多256次成功控制提交；终止通知最多3次，重复Done可有界重发完成确认。重复/迟到消息不分配第二个source任务、不重置窗口/共同期限。主端的下一Prepare可以作为上一摘要的隐式确认，两端保留12个一致编号的方向报告。

开始前要求全机活动业务最近10秒空闲；启动后，真实业务出现、路由引用变更、路径/epoch失效或截止即取消事务、撤销窗口并保留原Active。每台机器一次最多一项诊断；一次备用Attempt只启动一次事务，后续新备用可在5分钟冷却后重新准入。关闭Runner同时撤销并等待诊断source结束，再释放相同UDP socket/native路径。

报告绑定本地Path/Resource/Generation、方向SourceSlot、共同Session/Leg及Target；包含发送拒绝、IP准入、原生wire拒绝、加载RTT样本、接收缺口/相对到达变化。PathDiagnosticSessionStatus经成员状态传到IPC。它是诊断证据，没有把1秒接收收尾当16ms及时送达，没有授予QualityObserved或自动批准换路。

## 实际证据（本地artifacts）

| 产物 | 覆盖 |
|---|---|
| m6-diagnostic-formal-runner-first-20261012.json/.log | 10检查，真实Windows IPv6 UDP、HTTPS和正式Factory/Actor/Router/Runner；双方12窗口Done，约85.397秒、每发送端4.276MB准入IP字节、目标1Mbps，最大截止缺口0。内层网卡为内存，无Wintun/WAN。 |
| m6-diagnostic-formal-native-first-20261012.json/.log | 12检查，真实C++/TCP helper/认证管道/桥/HTTPS、正式组网；双方12窗口Done，约86.963秒、每端4.504MB准入IP字节、目标1Mbps。备用仍Standby/非Selected/无Business，原路径后续业务继续；raw IP及内层网卡为内存，无WinDivert/Wintun/WAN。 |
| m6-diagnostic-product-busy-20261012.json/.log | 9检查，正式实际UDP业务进入时双方Cancelled、额度撤销、原路径交付不受破坏，没有重建候选/socket。 |
| m6-diagnostic-session-model-expanded-20261012.json/.log | 390轮（13机制各30），1500检查；正常、Ready/Prepare/Prepared/Start/End/Report/Ack/Done/Completed单次丢失、重复、忙碌/取消。瞬时合成source与模型传输，不代表容量或公网成功率。 |
| m6-diagnostic-codec-20261012.json/.log | 124检查，字段往返、scope/目标/资源预算/保留字节变异、截断、NaN拒绝。 |
| m6-diagnostic-product-negotiation-20261012.json/.log | 138签名/协商检查，独立peer/server权限、匹配目标及旧默认，包含已有控制回归。 |
| m6-diagnostic-product-watch-20261012.json/.log | 44检查，实际HTTPS独立诊断授权与旧服务器回退清理；隔离八成员不是八终端。 |
| m6-diagnostic-product-windows-20261012.log | 92Windows设置/IPC/DPAPI/生命周期检查，诊断复选项默认关闭、依赖取消及旧后台禁止。未修改现用服务。 |
| m6-diagnostic-product-final-boundary-build-20261012.log | 最后边界/epoch/结束通知限制等代码的App/Service/Core Release零警告、错误。 |

首次控制Router构建有暂未补齐的partial方法及错误账本字段名（SendFailed，实际是Failed）造成失败，随后修复并编译。首次联调已发现隐式Ack需要保存接收端上一报告，修正后两端12窗口均存在。失败构建日志保留。

上述正式正例在最后epoch绑定、异常隔离及结束通知限制补丁之前执行；最终390轮控制模型与最终构建覆盖之后的代码，没有冒充重新跑过完整80余秒实测。原生正式正例为1Mbps，不把之前手动50Mbps底层实验偷换成正式自动50Mbps测量。完整Local/Package没有重跑；检查脚本已加入codec/session/UDP/native/busy入口。

## 仍未完成

自动质量窗口资格、相同方向/负载/新鲜度比较、质量不足解释、迟滞/冷却、双方批准及共同切换；硬故障下合格备用恢复。正式50Mbps、真实WinDivert/Wintun、公网QoS与严格NAT、八真机、冷启动/长时恢复/安装回滚等仍需执行，发布Gate不变。

当前诊断默认关闭、不能自动换路。设置说明其流量/时间，并可自行取消复选项；保存按既有流程重建该网络，空闲时操作。已发布0.5.3包及两端在用0.3.2没有被替换，公网协调尚未声明本次新增能力。所有业务继续禁止服务器或成员中继。

复现先build对应测试项目，用已编译DLL配绝对JSON输出路径：ManagedPathTests的--diagnostic-control-only/--diagnostic-session-model-only，MeshRunnerTraversalTests的--native <protocol-test绝对路径> --rounds 1 --output <JSON绝对路径> --diagnostic-runner-only/--native-diagnostic-runner-only/--diagnostic-busy-only。源码可按提交回退，不影响现有Lucky/EasyTier配置。
