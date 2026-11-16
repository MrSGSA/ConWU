# 验证结果与正式版差异

版本 `1.4.5-rust.1`，Windows x64 与本地 Arch Linux / WSL。证据保存在 `out/`，本地实验包附带必要日志和 JSON 结果。本轮未部署三机、未推送分支、未发布 Release。

## 已验证的主路径

| 范围 | 验证内容 | 证据 |
| --- | --- | --- |
| Windows / Linux Rust 测试 | 主从配对、SAS、独立网络、双向数据、伪造虚拟源地址拒绝、暂停恢复、签名退出、重启保留身份 | `app-test.log`、`linux-test.log` |
| TCP / HTTPS | 同端口反向连接，协议角色与 TCP 主动/被动方向独立，TLS pin，三连接分流及辅助失败回主连接 | 同上 |
| 兼容协议 | .NET 与 Rust 双向签名、P256/ECDH/HKDF、直连码、MeshLink AEAD、元数据、离网及 PKARR 加密状态；覆盖 .NET Guid 字节序差异 | `interop.log` |
| 六协议外层 | 两个临时 Linux netns，以真实 TCP/HTTPS/Phantun/Mimic/TCPRAW/FakeTCP 传输完成配对与双向业务 | `native-lab-result.json`、`native-lab.log` |
| 六协议虚拟网卡 | 上述六模式经真实 Linux TUN 完成内核双向 ping | `tun-lab-result.json`、`tun-lab.log` |
| WebUI | 独立内存后台、嵌入界面、两条独立网络、无 JavaScript 错误；请求重试、CSRF、Host 和票据边界 | `ui-smoke.log`、`rust-ui-smoke.png`、Rust 测试 |
| 持久化 | 只读旧 TCP 配置导入、Windows .NET HTTPS PFX fixture 导入后保留 SPKI、证书/pin 重开不变、下载重开重新校验、更新清理路径不能越界 | Rust 测试、`migration-test.log` |
| 协调 | 真实 TCP STUN、首配来源绑定、六种模式的同步轮次、同一设备不同网络公告隔离 | Rust 测试 |
| Windows helpers | MSVC Release 构建；Mimic capability 报告 XDP-only，无 WinDivert 回退 | `carriers-build.log` |

这些局域隔离测试不能证明校园网 NAT4 已打通，也不能代替 Windows 真实网卡、UU 串流或远程链路测试。Linux netns 使用直接 veth 作为可达外层。

## 性能实验

1280 字节负载、50 万次链路加密 + 解密、双方 Release、5 次取中位数。旧 .NET oracle 以相同负载和次数运行。数字中的 Mbps 仅按单份应用负载计算。

| 实现 | 编解码吞吐中位数 |
| --- | ---: |
| Rust 初始 AES-GCM 路径 | 5542.72 Mbps |
| Rust 优化后 ring 路径 | 19676.30 Mbps |
| .NET 对照，同轮测量 | 11058.72 Mbps |

优化后的 Rust / .NET 比约 `1.78`。这是 CPU 微基准，排除了网卡、驱动、网络、内存队列、调度、系统负载和 UI；不能推导为串流吞吐提升 78%，也未测出端到端时延或功耗优势。原始结果为 `benchmark-baseline.json`、`benchmark-result.json`，复现脚本为 `benchmark.py`。

## 功能状态

| 功能 | 当前状态 | 正式替换前仍需做什么 |
| --- | --- | --- |
| 当前一主一从、多网络、直连码/SAS | 已有完整主路径和本地验证 | 真实设备交叉版本与长时间恢复 |
| PKARR、可选协调、DNS 订阅 | 已实现签名、过期、序号检查和恢复控制状态 | 公共网关故障、真实 TTL 更新与长时间运行 |
| IPv6 | TCP / HTTPS 外层与 36 符号直连码已实现 | 真实双栈、IPv6 防火墙和网络切换；其余四模式暂限 IPv4 |
| 网关映射 | PCP / NAT-PMP / UPnP 自有映射及原地续租；本地模拟 UPnP 验证不先删映射、拒绝覆盖或删除他人映射 | 实际网关品牌/固件、续租、出口切换；本轮未操作真实路由器 |
| 原始承载 | 六协议 Linux 真实外层 + TUN 已通过 | Windows XDP/WinDivert/Wintun 和 WAN 实测 |
| UU 接管 | Rust 实现、多网络自动匹配、进程身份持有、计数 | 真实 UU 串流、UU 新版本，不能据编译通过就宣称接管成功 |
| 旧配置迁移 | 只读导入，TCP 身份/settings、Windows .NET TLS PFX fixture 测试通过 | 生产格式兼容、Linux PFX 转换及手工回退演练 |
| 托盘/系统服务 | 原生代码，独立服务身份 | 系统安装、开机、自启动、会话切换；本轮未注册服务 |
| 更新 | GitHub/Gitee 检查、Rust 资产筛选、下载/校验/恢复记录 | Rust MSI、Linux 安装回滚、后台恢复端到端验收；默认禁止安装 |
| 旧治理和多成员 | 明确拒绝，与当前双机产品方向一致 | 需要此类旧网络时单独设计迁移 |
| 旧 RejoinProof / EntryAdmission | 未逐项迁移；主流程使用直连码与 SAS | 如需免审批继承旧入口，补协议与对照验证 |
| 旧 native simultaneous-open broker / 历史 traversal API | 当前辅助轮次与候选交换已实现，深层研究路径未完全等价 | 专项 NAT 状态机和抓包对照，不能宣称严格 NAT 成功率对等 |

## 复现与测试开关

默认测试：`cargo test --locked --manifest-path rust/Cargo.toml --workspace`。Windows 边界代码还用 `--all-features` 检查和测试，测试仍只使用内存网卡及临时资料。

.NET 对照先构建 `compat/ConWU.DotnetOracle`，将 `CONWU_DOTNET_ORACLE` 指向它的 DLL，再运行 `conwu-core` 的 `wire_interop` ignored 测试。只在开发机需要 .NET 10。

六协议 netns 实验需要 Linux root、`ip`、`nft`、Python 与独立 helper；由 `build-native-lab.sh` 构建启用 `lab-api` 的专用测试后台，再执行 `native-lab.py` / `native-lab.py --tun`。仅临时 namespace 内修改路由和防火墙，finally 清理自己的资源。最终交付后台重新使用默认 feature 构建。
