# M6：有界负载诊断底层

基线`06c492d`。已完成诊断额度、报文、发送器、接收统计及TCP/UDP承载适配；正式自动质量控制流程尚未完成，`AutoQuality`继续拒绝启用。M0—M9整体目标未完成，未打新包、部署服务或替换在用组件。

## 实现与限制

`PathDiagnosticBudget`限制全机一个事务、同时一个窗口，共同90秒、256MiB，每窗口最多15秒。不同路径共用额度；取消事务撤销所有窗口，不能重新借维护或普通业务权限。数字是工程初值。额度表示本地准入，不能冒充对端收到或实际网卡发出。

MeshLink诊断类型8沿用每成员共享AEAD计数、epoch和重放状态，单独解复用，不能写入内层网卡或作为提名。SLQ1固定1280B载荷绑定事务/段/样本/发送相对时间；最多65536样本，8KiB位图及固定直方图。统计缺口、重复、乱序和相对到达变化，截止后不修改报告；零发送样本返回NoOfferedSamples，非法摘要和未知值不会产生零丢失结论。相对变化以首样本为基准，不是绝对单向延迟或应用送达期限。

原生本地管道增加Diagnostic类别4及pathDiagnostics=1声明；在最终IP注入前验证原路径资格、原生能力、精确PathId、窗口、速率与共同字节。UDP继续同一获胜socket/唯一接收者，只接受共享pacing队列的带额度入口，在发送回调按IPv4/IPv6开销计账。没有额度时连Selected也不能发送诊断；取消后普通业务仍独立可用。公网FakeTCP HTTP/SEQ、外层加密和无业务重传语义不变。

PathDiagnosticSender复用Windows高精度等待计时器，最多八样本一批，队列压力时等待。它不拥有socket或接收者，不修改全局计时设置；全出口pacing及队列限制仍有效。TCP工厂只在原生独立支持、捕获/账本可用且已配置pacing时准备可诊断适配器。

目前这些原语由隔离验证代码手动授权。正式Router没有创建诊断事务，未接双端/协调能力、Ready/Start/End/Receipt、忙碌业务保护、比较或自动提名；不能称为自动质量选路已交付。

## 本轮证据

| 本地artifacts产物 | 覆盖 |
|---|---|
| m6-diagnostic-budget-final-20261012.json | 27预算/密码/接收模型检查；共同时间/字节、默认拒绝、取消、身份、重复乱序及未知质量。 |
| m6-diagnostic-final-udp-20261012.json | 48检查；真实Windows UDP/shared pacing/MeshLink，准备owner结束后同socket仍工作；20样本最终按27440B外层IPv4/UDP计账，取消后普通业务继续。无Router策略/Wintun/WAN。 |
| m6-diagnostic-native-first-20261012.json | 48检查；真实C++/TCP helper/认证管道/UDP桥/pacing，20样本最终raw IP准入标为Diagnostic；手动额度、raw内存，无WinDivert/Wintun/WAN。 |
| m6-diagnostic-native-load-precise-20261012.json | 3段5秒目标50Mbps，收到49.98144/49.993728/49.995776Mbps；首段截止缺口8/24413（0.03277%），其余0。各段wireDenied/sourceRejected为0；累计73236准入IP报文、105899256B。单向、手动额度、raw/IP内存；非自动比较、WAN或及时送达证明。 |
| m6-diagnostic-legacy-wire-20261012.json | 78原有维护/握手预算、共享broker及正式native IPv4/IPv6检查。 |
| m6-diagnostic-legacy-protocol-20261012.log | 原生11协议用例通过，包括HTTP/bare边界、独占端口、错密钥、畸形IP、乱序/无重组和UDP边界。 |
| m6-diagnostic-final-app-build-20261012.log | 最后原生诊断期限资格补丁后的Core/Service/App Release零警告、错误。 |

关联.log同名保存。首次负载框架缺少内层Ping/Pong，12秒后第三段没有发送样本，最初错误抛摘要异常；已修框架保活及零样本未知结果。补保活后的Task.Delay发送器实际仅约21Mbps，未伪称50；改高精度发送器后取得上表证据。失败、21Mbps、约50Mbps原始产物均保留。

最后原生期限资格检查不改变正常有效窗口，最终构建及模型覆盖有效窗口；完整负载产物在该最后补丁前执行，不称为最后补丁后的重新实测。没有运行整个Package或真实安装包。

## 必须继续完成

正式双端与协调诊断权限及角色/目标/时长/总字节绑定；同一资源上的共同准备/启动/结束/摘要/取消；保护现有业务、全机调度、方向可比负载、加载RTT、队列及证据新鲜度；3个连续5秒窗口、30秒驻留/60秒冷却、双方批准与共同提名；硬故障合格备用恢复。真实WinDivert/Wintun、校园网QoS/严格NAT、八真实机器、长期运行及新版包/回滚验收仍缺。

复现时先构建对应测试项目，用已编译DLL和绝对输出路径运行ManagedPathTests的--diagnostic-budget-only/--diagnostic-socket-only，或MeshRunnerTraversalTests的--native <out/native/udp2raw-protocol-test.exe绝对路径> --rounds 1 --output <JSON绝对路径> --diagnostic-only/--diagnostic-load-only。仅隔离验证，不应在实际组网自动压测。

protocol-test禁止装入产品。out/native已重编译，0.5.3的原Package收据不再匹配新的开发二进制，不能借旧收据SkipBuild打包。保留的发布bundle/ZIP及两端在用0.3.2服务不变；源码可按提交回退，无Lucky/EasyTier或全局网络配置改动。
