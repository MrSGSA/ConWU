# 0.5.6 未具备环境的验收步骤

本文件是最终报告的人工步骤草稿。尚未执行的项目不因步骤已写好而通过。

## 校园网 NAT4 与公网双主动

状态：Blocked。现有两端显式TCP入口的成功不证明双方严格NAT的双主动能力；缺少经过验证的SO正例拓扑和两公网IP、多端口反射/观察设施。

1. 使用两台Windows和允许合法SO包序的受控NAT，先抓包确认映射/过滤行为；不能只把路由器配置命名为“NAT4”。观察设施须有两个真实公网IP及不同端口，不把Cloudflare地址当原始TCP反射点。
2. 保留默认显式TCP入口作为对照；实验网络选择“实验TCP打洞”，UDP降级、预测、来源学习及概率探索分别保持关闭。候选必须实际声明SO；记录Lease、Attach、Attempt、真实tuple及数据profile。
3. 使用正式配套native和Wintun，双方无显式入口，验证交叉SYN、HTTP/udp2raw握手、MeshLink共同提名和完整1280B IP业务。各确定性正例30轮；启动偏差0/±100/±500ms、握手单包丢失、重复、错误ACK、旧包和seq回绕按机制覆盖。
4. 每轮共用8秒截止，不为HTTP、认证或提名重新续时。受控无损目标3秒；记录首SYN、认证、提名及首次/稳定业务的本机单调耗时。
5. 在对端入站观察点验证有效运行窗口的内核RST/额外SYN+ACK；记录捕获点、丢包、offload和native控制账本，不把本机“已拦截”当线上零RST。
6. 校园网独立列总数、成功数、时间和端口/映射变化；限定方法最多两轮/共同机会窗及全机预算。未找到路径返回NoDirectPathWithinBudget，不无限扫描、不改成服务器或成员业务中继。

统一本地复现入口只接受已实现的Local profile：

```powershell
pwsh -NoProfile -File scripts/Invoke-TraversalValidation.ps1 -Profile Local -OutputDirectory artifacts/manual-local
```

它不加载驱动、不证明上述公网Gate。真实设备网络命令须先准备本轮私有身份/端点/控制文件，再使用仓库已有`scripts/Invoke-TraversalNetworkNode.ps1`或`Invoke-NativeRouterNetworkNode.ps1`；不要虚构尚未实现的ControlledNat/Wan脚本参数。

## UDP 同socket、prflx与真实PMTU

状态：Blocked。需要稳定端EIM/ADF与目的相关映射端的正例，以及严格过滤丢弃第一包的负例。

1. 单独实验网络显式允许TCP+UDP和UDP降级。日志关联STUN→检查→prflx→提名→业务的同一SocketResourceId；实际入站源需发生变化。
2. 稳定端先向hard端公网IP预热ADF，hard端随后发送；变化来源经认证和反向检查后才提名。APDF丢弃第一包的负例不得伪称能学习来源。
3. 每正例30轮；结束Attempt、取消失败候选、丢Confirm、切网后验证获胜socket仍承载Wintun，旧消息不能复活退役资源。
4. 双方向测试1280B内层IP、1344B UDP payload、IPv4外层1372B；设置DF并核对实际分片。1400B UDP payload只作余量，失败不自动拒绝已满足1372B需求的路径。
5. 模型/回环成功与公网吞吐分别记录。默认健康FakeTCP不被更早连通的UDP抢占；UDP质量不足应显示降级，不加入业务重传。

## 八台真实Windows

状态：Blocked。当前只有两台独立Windows。隔离实例/模型测试不能替代八终端。

1. 八台装同一配套完整包，先每台执行实际`StreamLink.exe --verify-bundle <报告.json>`。配置同一允许的公网协调服务；创建者依次通过短码批准七个成员。
2. 在每台记录本机七邻居的固定IP和直接可达性；共验证28条无向关系。双向完整MTU、50Mbps方向回归按实际出口总带宽顺序执行，不要求七条各占50Mbps。
3. 同时加入/切网/恢复，核对全机60pps、维护24pps、控制字节和资源配额；高成本策略保持关闭。记录公平排队、资源峰值及释放，不把每peer预算相加当合规。
4. 故意阻断B-C，同时保留A-B/A-C；B-C必须明确未直连，A不得转发它们的业务。关闭创建者，已有其他成员直连应继续，授权撤销时效按目录策略验证。
5. 保存每台SCM、OS、native/驱动hash、网络拓扑和pair结果；没有测试的pair不填成功。首次时间、稳定恢复、p50/p95由真实样本计算，不由模型外推。

## 重启未登录、休眠、物理切网

状态：Blocked，需用户安排允许断开远程管理的窗口和可用恢复手段。

1. 两端先从设置安装后台服务；核对LocalSystem/Auto和恢复动作、实际完整包路径。备份受保护配置及上一个完整包，不卸载共享WinDivert/Wintun。
2. 重启两端，不登录桌面，待服务自动启动后从另一管理通道核对SCM、虚拟IP和真实业务。记录从系统/服务Ready到首包及稳定确认；SYSTEM任务已运行不等于完成这个Gate。
3. 单端睡眠再唤醒、改变Wi-Fi/以太网出口，分别验证观察过期、旧候选退役、健康路径保留和恢复。无关接口事件应不无条件断开Active；不得通过关闭VMware桥接来获得通用结论。
4. 故障恢复至少记录FirstBusiness、回溯StableBusinessStart、StableBusinessConfirmed；普通ping成功只算StablePath。没有实际业务时不称业务稳定恢复。

## 视频播放和单向时限

状态：Blocked，需人工运行应用；持续合成UDP负载只能证明传输性能。

1. 两端已通过新虚拟IP直连后，用实际Moonlight/Sunshine或其他应用运行至少60分钟，固定编码/分辨率/50Mbps和同条件基线，采集应用丢帧、卡顿及加载RTT。
2. 记录软件队列/接收计数和应用播放统计。没有可证明≤2ms的双端时钟误差，不宣称50ms单向deadline或迟到率通过。
3. pacing、备用、AutoQuality等分别A/B，默认保持关闭。吞吐下降超过2%或尾延迟变差时不默认启用；不以更低码率替代原50Mbps目标。

## PCP/NAT-PMP、原生IPv6及同协议在位回退

状态：Blocked或未验收；需要实际支持的网关、原生双向IPv6或已安装0.5.x。

- PCP/NAT-PMP只删除本软件nonce/映射所有者匹配的租约，核对实际返回端口、租期、epoch及端到端可达性。内层网关成功不证明外层CGNAT已开放。
- 原生IPv6须真实双向路由、防火墙及完整外层报文尺寸。不能用Teredo、VPS业务转发或两个link-local地址代替公网IPv6。
- 0.5.5→0.5.6→0.5.5的同网络在位升级另行记录，保留较新的成员撤销目录和授权；0.3.2→0.5.6独立身份→0.3.2的验收不能替代它。
