# 702ee2e 复审后的有限推进

唯一增量范围为 StreamLink-PersonalFeature-Review-702ee2e 中 PF2-01～05，基线完整 SHA 为 702ee2e2ef11af11683fc049407acd5c1bfd161c。既有 SO、来源学习、共同提名、UDP 同 socket、HTTP/SEQ 与网卡工厂不重做；不增加协议、业务中继或公众 1.0 范围。

## 代码变化

- PF2-01：测试判定用统一的 ScenarioVerdict/ExitCode；公网 TCP 无显式来源变化要求时是 NotApplicable，不依赖不存在的 HostFactory。准备、实际检查、业务、来源、负载与清理分别记录；基础设施失败不能通过 NoDirectPath 负例。夹具版本 PF2-01-v1，保留旧失败。
- PF2-02：Runner 日志记录取消后每项 task 状态；来源角色测试另落盘 PID、最后阶段、实际 capture/native/adapter 所有权。原 server-role 十秒门槛不变。官方三秒 close 性能门槛不变，有限额外观察只确认原 owner 是否完成，不变成性能通过；PnP 未收敛时停止重开。
- PF2-03：双机脚本支持 C0 `Kind=legacy` 和 C1 `Kind=tcp`，来源偏移角色单独配置；测负载才明确授权本次质量请求。整例 lifetime=120 秒仅容纳准备及两方向顺序 50Mbps/20秒，不改变八秒 SO 共同期限。每节点进程外 watchdog 仅回收自己启动的测试树。支持指定独立协调 JSON；控制可达、数据可达、真实 tuple 与底层范围分别记载。
- PF2-04：增加已加载自研设备的实际 READ/WRITE/IOCTL/NDIS/取消工具、受保护 Gate 发行、Verifier 原始状态采集、签名后身份重固定。不是模拟驱动，也不会在宿主自动装载。新增工具仍需真实来宾测试；完整 PnP/电源/故障注入覆盖未完成，不能把这些代码缺口写成纯签名阻塞。
- PF2-05：固定 personal-feature.2，完整 Windows、协调、研究及源码包。研究工具在 Windows 包复用已有精确 .NET runtime，研究 ZIP 可单独运行。

## 本轮已经确认的边界

统一判定表及真正协调连接失败负例可在本机完成。来源 Runner 的小用例和六类边界可用模型 raw/mapping、真实 HTTPS/native worker 完成，不能晋升物理 NAT 或 Wintun C1。

Wintun 3.61 秒历史 Fail 不变。后续每条真实 close 的实际 elapsed、资源完成、PnP 与重开独立记录；不以新模型结果改旧 Fail。不得强删残余接口、提前 FreeLibrary 或启动第二 owner 绕过等待。

单 Windows 上尝试两个完整 Runner 时出现网卡创建 4319；它不是双机 C0，通过或失败均不能直接外推真实双机，根因未确认。没有为此改生产 GUID、网段或打洞逻辑。当前没有两个可用设备时，双机 C0/C1 是 BlockedExternal；不能用旧 overlay 的底层 30 轮或同机内存网卡成绩代替。

## 下一次人工复验（不是本轮无限重试）

1. 保留 0.3.2；确认 Akane SSH 及独立测试端口可达。当前个人包及测试 harness 的组件/服务/Core 文件 hash 要对应，记录 actual Service URI 和 health Mesh4/Traversal1/relay=false。
2. 在匹配 HTTPS 协调下运行双机 `Invoke-PersonalMeshPair.ps1 -Kind legacy -DataRoute host -Rounds 1 -MeasureLoad`。这是 overlay 上的既有显式入口回归，不声称新增物理 NAT；若有独立、已验证公网入口，再单列物理 C0。
3. C0 完整 1280B 双向、正常结束及负载达标后，运行 TCP C1 correct，再 local-offset/remote-offset 各一例。偏移公告侧与需要学习的接收侧分别验证。接着使用生产物理采集 `DataRoute public`；旧 overlay 不算新 NAT 覆盖。先看候选及真实 tuple，不扫描公网端口刷新成绩。
4. UDP 的底层必须支持 1344B payload/1372B IPv4 且 DF 的实际发送。低 MTU 的旧失败不删，不降低载荷或靠分片通过原门槛。
5. 自研遵循《PF2-驱动实验流程》。缺 VM、签名、授权时不在日用机实验；来宾通过后才分两次安排 C2/C3 和目标签名/加载。

默认能力与本人已用能力不同：SO/来源学习/同 socket UDP 接线和独立开关保留；预测/概率/后台压测未因本轮自动启用；自研仍明确可选且准入阻塞，Wintun 不冒充自研。推荐等级按实际 C0/C1 和驱动证据决定，未过时不接管日用。本人串流仍 PendingUserTrial，公众批准 false。
