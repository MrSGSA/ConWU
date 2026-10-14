# Windows 侧固定版本验证清单

本清单不授权生产部署或关闭系统安全措施。测试应有独立恢复入口，不能只靠待测隧道维持远程控制。

## 0. 构建与来源

保存当前 HEAD、工作区 diff、完整源码清单。执行 `Test-Rc2SourceFix.ps1` 后检查 manifest、每步日志、fixedSourceBytes；若修改过代码，另开新的输出目录与来源记录。默认不执行真实网卡测试；`-RunFullCore` 不允许用 StartAt 或跳项伪装全套。

C# 和 PowerShell 在交付容器未编译/运行，第一道工作是构建校验，不能直接安装源码修复版冒充已测成品。附加期望：原 HTTP/bare 序号、现有 parser/SO/Router/capture/protocol/queue 回归不退步。

## 1. UI 并发与界面

运行原 ControlTests（已加入 UiPatchTests）及 Rc2PortableTests。确认管理员保存等待旧 worker 退出时，UI补丁确实排队；最终只变更被编辑字段，保留新网络/诊断配置。相同ID相同补丁跨无关变动仍返回原结果；失败重放仍失败；授权排队撤销后不执行、不返回状态。

桌面上修改名称→移焦日志→跨三次轮询：两个草稿不丢。其他窗口修改同字段时出现冲突提示；撤销采用新值。分别测试后台断开、超时后原ID重试、回复迟到、与旧v1后台交互。名称/日志保存期间检查 worker/Lease/Active 没有重建。UI screenshot/可访问性不要用 helper 测试代替。

## 2. 首次安装和跨账户升级

准备标准用户 A、管理员 B 与 C、未授权用户 D。固定候选包验证通过后，在隔离实例/机器：

1. A 从普通桌面运行 Install-Service.ps1，UAC 提供 B 凭据；交互明确填写 A，核对显示的账号和SID。
2. A 日常 UI 能读受限状态/改名/日志/启停；不能获取完整 profile、私钥或管理员设置；D 和远程管道拒绝。
3. C 升级同实例，原授权仍是A；不能因提升账号变化而变成C。
4. UAC或账号确认取消：授权和现有服务/前台不变。
5. 注入安装失败，验证授权与服务恢复分别报告；不能因其中一个恢复失败跳过另一个。
6. 直接传SID、组名、未知用户都拒绝。现有授权与 --ui-user-account 不同应明确报错而非改授权。

原 Test-InstalledRC 是同账户隔离安装，只能证明它声明的范围。

## 3. 官方适配器生命周期

先运行 no-driver watchdog 自测，再使用当前源码重建的 streamlink-tun.dll 与已核验官方 wintun.dll 运行隔离试验。核对测试程序集、两份DLL、源码构建收据。

逐轮查看 stages.jsonl。重点识别 exclusive-wait / native-session-end / native-adapter-close / wintun-library-free / bridge-library-free 哪一步未返回。

3秒原截止和“立即不存在”Fail必须保留。若关闭完成而稍后PnP才收敛，应先解释设备生命周期并制定新的预先版本化指标，不能事后把旧失败改为通过。超时必须保留自有child PID、线程状态、日志，未抓真实调用栈不得报告已抓。

隔离100轮仅用于故障收束；后续仍需同进程循环、句柄/网卡/规则增长、安装服务停启和不影响外部接口验证。不得删除共享驱动或用先FreeLibrary/强抢端口掩盖未退出。

## 4. 研究驱动

Rc2ResearchTests 不加载SYS，以真实Read/Stop/Dispose方法和三个线程验证锁序。然后在可恢复的隔离驱动实验机上，合法签名/WDK/Verifier条件下验证预取消、出队取消、Drain/Cleanup/Halt竞争。PendingReads=reservation，QueuedReads=真实队列，均须正确收敛。超过16次预取消后正常read可继续，空队列无循环work item。

在上述条件前不生成“驱动可正式替代”结论，不加载到生产、不关闭签名/HVCI，不把WFP观察样机称为注入后端。

## 5. 固定核心和业务 Gate

旧兼容认证超时继续单独追踪首次状态分歧，不能用后续Pass覆盖。Windows编译/核心测试通过后，才做两机SO/来源学习off/on。对等映射、实际tuple、握手、认证、提名与Wintun数据必须同一资源；没有显式入口的正例与原P→Q入口分开。

双向顺序50Mbps/20s、60分钟实际业务、pacing off/on、安装业务迁移/回退、六分钟双端控制中断、无人登录/休眠、八台Windows沿用原门槛。没有相关设备就记录具体外部阻塞。最终仍以独立固定包与实际证据决定是否可以发布1.0。
