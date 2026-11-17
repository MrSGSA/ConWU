# Rust 替换验证

源码版本 `1.5.0`。本表记录发布前的隔离与兼容验收；原始证据保存在本工作区 `out/`，具体安装包的三机试切与发布结果另见 Release 随附的 `verification.json`。

## 已完成的验收

| 范围 | 结果与证据 |
| --- | --- |
| 核心与后台回归 | `production,local-install` 配置下 Windows 后台 30 项、Linux 后台 28 项通过；核心、成员 / traversal、安全分别 3 / 3 / 2 项通过。见 `parity-windows-production-current.log` / `parity-linux-production-current.log` |
| 旧协议对照 | .NET / Rust 双向签名、AEAD、元数据、直连码、RejoinProof、EntryAdmission、v3 traversal 和 PKARR 加密状态已验证；包含 Guid 字节序差异 |
| 六协议 Linux | 真实外层配对、双向加密数据；最新六协议协同辅助 + Linux TUN 双向通信全部通过：`parity-assisted-tun-current.log` |
| 受管 FakeTCP | 同源观察、SLF1 身份认证、SLN1 实际路径提名和双向 TUN 已通过：`parity-managed-tun-current.log` |
| Windows 受管 FakeTCP | 实际 WinDivert broker、协调发现、SLF1 / SLN1、Wintun / TUN 双向通信及断开重连通过：`parity-managed-cross-path-fixed-current.log`。修复了旧组件不能读取规范化路径前缀的问题 |
| 原版网卡交接与回退 | .NET → Rust → .NET 真实网卡交接通过，虚拟 IP、原代次日志及排他锁一致，日用服务进程未改变：`parity-windows-legacy-wintun-result.json` |
| Windows / Linux | 六协议均通过真实 Wintun / TUN 配对、双向 ping、断开重连及从机重启；每轮保留先前网络，最后六网全部恢复：`parity-cross-six-current.log` |
| Windows 纯 XDP Mimic | 跨端配对、真实网卡、重连及多网络重启组合通过；重绑期间一次启动超时后由后台重试恢复，已修订有界启动等待 |
| MSI 安装与升级 | GUID 隔离实例安装成功，MSI 1→2 升级成功，两个网络的编号、虚拟 IP 和独立端口保留 |
| 普通用户 | 非提升用户可通过 broker 管理后台，无法读取后台私密文件；两个 Wintun 均就绪：`parity-msi-user-*.json` |
| MSI 失败回退 | 故意损坏非执行组件摘要的 MSI 被拒绝；旧程序哈希、运行中的服务和两个网络恢复：`parity-msi-failure-rollback.log` |
| 完整维护源 | D 盘保留当前完整 MSI，登记到 Windows Installer SourceList；上一版含完整程序、设置和原 MSI |
| Windows 自带更新 | 正常 UI / CSRF 命令触发已下载 MSI，后台、两个真实网卡、网络身份和维护源保留；故障包拒绝并恢复，见 `parity-windows-update-fixed-result.json` / `parity-windows-update-fault-result.json` |
| Windows 托盘与服务启动 | 普通用户启动停止中的服务、broker 状态及私密资料拒绝访问通过；托盘冷启动 / 正常退出独立复测通过：`parity-msi-user-start-current.json` / `parity-msi-user-tray-final.json`。首次组合测试的 12 秒托盘等待不足，35 秒复测通过 |
| Linux 自带更新 | 独立 systemd worker 不被旧服务进程组终止；成功更新与启动退出 42 的故障候选回退均恢复真实 TUN、协调及网络身份：`parity-linux-update-result.json` |
| Linux 随包安装器 | 首次安装、覆盖安装、启动失败回退、保留资料卸载均通过，包含真实 TUN 及完整上一版设置：`parity-linux-install-result.json` |
| IPv6 | 隔离双栈网络内 TCP、HTTPS 经 36 位直连码配对、真实 TUN 双向通信通过：`parity-ipv6-tun-current.log`；没有据此宣称公网双栈或其余四种承载已通过 IPv6 验证 |
| 生产资料只读导入 | 笔记本、台式、Linux 均已演练；设备、成员、目录与撤销高水位、订阅及 PKARR 身份保留，未启动导入网络 |
| Linux 协调资料 | 四份协调网络记录语义一致，Cloudflare 来源信任和远程管理设置保留：`migration-linux-parity-20261117/audit.json` |
| 协调诊断 | 实例挑战应答、无缓存健康检查、证书状态、HTTPS 源站核对、修改外部地址不重启监听、重配后释放端口，Windows / Linux 专项通过 |
| STUN 与 DNS | 默认保留原 87 项 TCP STUN；探测失败轮换至列表后部的实测回归通过；订阅优先于首次临时入口 |
| 公共 PKARR | 不可用网关与两个公共网关组合，发布独立短期测试身份、解析和关闭后重开检查点均通过：`parity-pkarr-public-current.log` |
| 生命周期 | 删除时取消发现和持久化等待，确认任务退出后再复用端口；helper 正常 EOF / RST 退出，超时关闭返回错误 |
| 界面文本选择 | `test-web-presentation.py` 覆盖实际轮询期间的鼠标拖选、跨行日志、概览、输入框和弹窗选区，以及恢复绘制后补齐日志；同一脚本验证 IPv4 默认码与显式 IPv6 码 |
| XDP 安装检查 | `netcfg -q` 返回 0 但未注册驱动的情况已在台式复现；随包安装脚本改为检查服务和网卡绑定，安装后物理网卡上的 Mimic 接收入口就绪；已安装状态重复执行不会重装驱动 |
| 心跳延迟 | TCP／HTTPS 的单连接和分流连接回归包含跨心跳周期检查，同一 nonce 的重复回复不再累计等待秒数 |
| 首次申请故障反馈 | 缺少本机承载组件且直连码允许协同探测时，立即保留本机错误并写入日志，不进入 STUN 等待；没有取得成员身份 |
| 选区与新申请 | 实际界面轮询中保留概览选区，同时刷新新申请计数；加入阶段与后续失败原因在原表单中显示，输入的码保留便于重试 |
| XDP 队列检查 | 新增不附加捕获规则的 RX/TX 实际队列检查；已在本机物理 Ethernet 验证就绪，安装脚本正常重复检查不重绑网卡 |
| 协调同源与调度 | 当前开发分支 Windows 后台 37 项通过、2 项忽略，Linux 后台 34 项通过、1 项忽略；包含固定观察源 IP／端口的真实 TCP／TLS 套接字检查、首次过期重同步上限、旧轮次重放、响应大小限制和成员轮次续调度。核心、成员关系与安全检查分别 3／3／2 项通过；未运行的旧版 oracle 项目继续保留忽略。见 `coordinated-punch-20261117/windows-tests-current.log`、`linux-tests-current.log` 与两平台的 `*-tests-final.log` |
| 双 NAT 协调与重启 | 六种承载均在双 Linux SNAT、conntrack 入站过滤、无静态 DNAT 且禁用网关映射的隔离环境中，通过首次 SAS 审批、逐字节双向加密报文及从机后台重启复连；入口刷新固定 60 秒，用于复现并验证断线唤醒。使用内存虚拟网卡，原生组件沿用既有构建。TCP／HTTPS／Phantun／Mimic／TCPRAW 在一轮中通过，FakeTCP 在为 WSL／NTFS 的 Unix socket 提供私有临时文件系统后单独补验通过。见 `coordinated-punch-20261117/dual-nat-six-final.log`、`dual-nat-faketcp-final.log` |

双 NAT 夹具验证的是所述 SNAT 和过滤策略，未完成校园网目标相关映射、随机端口分配及公网双端严格 NAT 的实测；不据此宣称所有 NAT3／NAT4 可穿透，也不将其作为实际串流性能。上述接续开发仍使用 `1.5.0`，三机安装与发布结果由对应候选包的验收记录确认。

## 2026-11-17 日用修复与 NAT 实验

2026-11-17 新增日用修复的源码验收：Windows 后台最终 40 项通过、2 项忽略；用户授权正式交付后，以低优先级和两个逻辑核串行补验，Linux 后台 37 项通过、1 项忽略，核心／成员关系／安全分别 3／3／2 项通过，未提供的旧版 oracle 保持忽略。实际内嵌 WebUI 的 Playwright 验证覆盖审批／拒绝后卡片与角标收尾、移除未批准申请、UU 旧状态兼容及网络过滤、更新结果手动关闭和自动收起，未出现页面 JavaScript 错误。

Windows Mimic 默认 WinDivert 的修订已通过原始承载 14 项协议回归，以及 Windows Wintun／Linux TUN 的强制协调首次 SAS、双向报文、断开重连和 Windows 后台重启。TCPRAW 同样通过该跨平台组合。证据为 `out/daily-fixes-20261117/windows-tests-final.log`、`linux-tests-current.log`、`windows-raw-tests-current.log`、`web-presentation-final.log` 和 `windivert-cross-final.log`。此处为受控虚拟链路，未据此宣称 WLAN 日用长稳或新版 MSI 安装通过。此前纯 XDP 的历史验收不等于 AX211 WLAN 的队列稳定性；本轮实机已出现重复 TX bind `0x80070017`。

生日碰撞首次独立 TCP 实验在缩小的 1024 端口空间中，一端稳定一端随机的 64×64 组合成功 3／3，双端随机组合成功 0／3；双方 WAN 的主动 SYN 和变化的源端口已记录，命名空间清理通过。证据 `out/lab/birthday-601f9c78/`，算法来源、边界和复现入口见 `docs/NAT穿透实验.md`。未接入产品，也没有公网成功率结论。

同日用户报告笔记本连接台式机的 UU 频繁卡顿至 999ms，停止并行构建和网卡／承载实验后确认明显缓解。只读观测显示当前为 UU UDP 经 Phantun 传输，两端 ConWU 心跳约 17–20ms；采样未复现持续 999ms，台式虚拟网卡历史接收错误计数 1790 在两次读取间未增加。本轮开发测试干扰是当前最强线索，尚未隔离出 CPU、共享驱动或网卡重建的独立贡献。后续日用会话期间停止此类测试；跨平台脚本新增真实生产服务／SCM PID 校验和活跃流量拦截。诊断证据位于 `out/uu-latency-20261117/`，未安装开发改动或更改日用 UU 设置。

## 性能数据

1280 字节负载、50 万次链路加密 + 解密，双方 Release，五次取中位数。`benchmark-result.json` 中优化后的 Rust 编解码为 19676.30 Mbps，.NET 为 11058.72 Mbps，约为 1.78 倍。该数值只代表 CPU 微基准，不包含网卡、系统驱动、外层传输、实际链路或串流延迟。

## 最终构建与试切

- 每次修订都核对最新源码的 Linux 静态 musl 包、MSI 同版本覆盖、三机实际程序摘要与网络恢复；公网文件传输和用户确认的 UU UDP LAN 路径另见随包 `verification.json`，不以 WSL 通信代替公网验证。
- IPv6 公网双栈仍需具备对应线路的独立实测；目前的三机 IPv4 验收不会将其计作已通过。

隔离 namespace 和 WSL 可达链路不能证明校园网 NAT4 已穿透。Windows 测试路径临时将 WSL 外层 MTU 从 1280 调为 1500，并在 finally 恢复；现有 1280 字节虚拟 MTU加外层开销需要更大的外层 MTU，不能把该实验环境的分片失败归因于 Phantun 本身。

所有必要项完成后，使用同一份已验收构建整体替换；任何必要项失败都继续修复，保留现行版本及回退资料。完整清单见 [PARITY.md](PARITY.md)。
