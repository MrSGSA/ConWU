# 1.0.0-rc1 人工验收与外部阻塞

本轮不宣布 1.0 正式发布。以下步骤沿用原门槛，当前本机模型、回环或单张 Wintun 的成功不能替代它们。使用最终报告指定的同一包与 SHA256；两端记录 Windows 版本、接口、物理出口、组件哈希、功能开关与开始时间。

## 隔离安装、升级、回滚

在管理员 PowerShell 执行仓库 `scripts/Test-InstalledRC.ps1 -Bundle <固定包的windows目录> -OutputDirectory <新证据目录>`。脚本随机创建 `StreamLink-Validation-<GUID>`，配置与安装目录均隔离，业务保持禁用，测试实际 SCM、受保护 RPC 的 PID/ServiceReady、候选失败/双失败、同网 DPAPI 与 SID 恢复，最后只清此实例。它不能代替 0.5.6 的实际跨版本迁移。

跨版本测试前：保存原完整包/哈希、ImagePath、启动方式、配置加密备份、已知成员目录 revision 和授权 SID。先在独立 Windows 实验终端做 0.5.6→RC→0.5.6，保留最新撤销目录；不能以旧 profile 直接覆盖已知撤销状态。断电/坏包/启动失败后核对旧服务可用、配对和密钥没有重建。业务应恢复，原包和最终 RC 都进行双向测量。实际生产切换前说明会中断 StreamLink 当前连接。

## 真正的两端 FakeTCP 资源与穿透

准备两台实际 Windows，空闲独立 TCP/UDP 测试端口，先确认端口未被现有 StreamLink、EasyTier、Lucky 或其他进程占用。允许控制信息借已有管理连接交换，但测试承载出口不得走该旧 overlay，也不得走服务器或成员转发。

先执行现有 `StreamLink.EndpointPoc --network <private配置>` 或 `--router-network`，对应 `scripts/Invoke-NativeRouterNetworkNode.ps1 -Configuration <配置>`；完整 IP 业务用 `scripts/Invoke-TraversalNetworkNode.ps1 -Configuration <配置> -Output <新文件>`。测试工具从相同候选提交发布；不要把私密配置、密钥、完整邀请公开到 GitHub。脚本会建立并移除精确命名的临时规则，不能开放全局端口或改默认路由。

抓包至少有本机及独立对端，受控 NAT 的外侧也需要观测。先用探测及抓包确认实际映射/过滤；不能仅凭拓扑名叫 NAT4 就认定行为。持续持有的源 socket/Lease、AttachId、代次、实际 tuple 与数据路径需可关联。Armed 前捕获/RST 抑制已就绪；有效运行窗口不得泄漏非预期内核 RST；helper tuple 正常，native 不二次 bind 同一个 P。30 次正/负例，覆盖取消、第二实例抢端口、子进程退出、旧包与资源回收。

SO 保持原 HTTP/bare/SEQ profile、无业务重传：交叉 SYN，A/B 提前100/500ms，一次握手包丢失，重复/旧 SYN/RST，错误 ACK 与回绕。整轮仍是 8 秒共同期限，不能为每阶段重置。明确失败阶段，错误/旧控制零次晋升 Active。同一 TCP tuple 只一套握手状态。

来源学习、校准预测、UDP 增强分别用同一 binary 做 off/on：记真实观察目标/时间/源资源/实际端点和完整双向 FakeTCP/MeshLink 业务。关闭算法时失败、开启后成功才算新增覆盖；新增报文/源数量也要记。不要把真实 TCP connect 或单个 SYNObserved 当作 LegacyPayloadVerified。

## 私网 UDP、PMTU 与强弱证据

保留获胜同一 SocketResourceId，STUN→检查→prflx→提名→真实业务不能重绑或更换唯一接收者。至少一个合法首包到应用才可来源学习。认证见证必须覆盖本次授权对端 IP 的全部端口；当前单个声明端口的见证不能授权随机扫描。经验 EIM 的 4 训练+2后来留出仍属独立 opt-in，不保证对端映射；双方无合格稳定端须有界退出。

当前 1280B 内层 IP 对应约1344B UDP payload /1372B IPv4包；抓包核对 DF 与未分片实际包长。1400B余量探测不能单独证明未分片。真实协议堵塞和两端完全随机 APDM+APDF，应保留 NoDirectPathWithinBudget，不开启业务中继。

## QoS 与现有链路保护

在两机都空闲时做同条件 50Mbps、20秒、先一个方向再反向。沿用原零丢包/吞吐与延迟门槛，不用诊断模块较宽的 qualification 阈值替换。至少60分钟真实应用/串流，记录连续丢失/迟到/冻结、加载 RTT p95/p99、队列年龄与实际应用丢帧；缺时钟同步不得宣称单向 deadline 通过。

分别比较兼容 pacing 开/关、零速率与正常额度，记录父进程最终 WinDivert 注入、实际接口/源地址、队列/过载拒绝和 fence。饱和、单子进程故障、测速端口冲突、撤销、设置保存和加入新成员不能无界压垮健康 Active。空载低 RTT 的 UDP 不可抢健康 FakeTCP。原 24/104098、13037/18749994 的历史 Fail 继续保留。

## UI、权限、生命周期与八台设备

真实普通账户：受限状态/改名/日志等级/启动停止；无法读 DPAPI、完整管理管道、私钥、任意日志路径或完整导出。实际另一 SID 与远程 SMB 拒绝；记录 PID 校验与授权 SID 更新/回退。当前 linked-token 工具 Win32 267 不是已通过的权限测试；请从真实非提升桌面运行。

GUI 首次6位配对→核对验证信息→明确加入/批准，检查创建/加入/停止反馈、取消/失败/重复点击、关闭 GUI 后服务是否继续。1366×768与1920×1080、100/125/150/200%及混合双屏，保存/取消可达、Tab顺序、UIA/Narrator、高对比、减少动画。当前250%离屏 DrawToBitmap不是各显示器验收或屏幕 FPS。

八台实际 Windows：每台最多7 peer，全网28对，各对独立直连，B↔C失败不能经 A 转发；困难 peer 不饿死其它 peer；全机2轻/1重、60pps、默认8 UDP资源以及维护预算核算。分别未登录冷启动、休眠/唤醒、Wi-Fi/有线切换、地址/路由变化、helper失效、native崩溃、服务重启。计首包、稳定区间起点、稳定确认三个时间，不改15秒目标计时起点。

双端只阻断协调 HTTPS 至少6分钟，已有 Active 应继续；单独测试反射/续租/DNS失败。公告/授权/映射过期各自记录，不混为业务活跃状态。测试只针对该软件的独立规则，结束恢复；不关闭安全中心、签名策略、VMware桥接或网卡 offload 来取得通过。

## 自研驱动

只在可恢复的独立 Windows 驱动实验机，参考 `docs/driver-validation/RC1-Manual-Gates.md`。现有研究 SYS 未签名且未加载；NDIS TUN 的真实内核收发/PnP/电源/取消/100次生命周期、Verifier/HVCI/HLK、权限负例与签名均未通过。WFP 样机仍是有界观察，实际注入未完成。未全通过前不得替换默认官方 Wintun/WinDivert，也不得关闭安全策略装到当前生产终端。
