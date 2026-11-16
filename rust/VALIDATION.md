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

## 性能数据

1280 字节负载、50 万次链路加密 + 解密，双方 Release，五次取中位数。`benchmark-result.json` 中优化后的 Rust 编解码为 19676.30 Mbps，.NET 为 11058.72 Mbps，约为 1.78 倍。该数值只代表 CPU 微基准，不包含网卡、系统驱动、外层传输、实际链路或串流延迟。

## 尚未完成的正式切换门槛

- 最新源码的 Linux 静态 musl 包、三机候选实际链路、UU 实际串流路径与最终恢复组网。
- IPv6 公网双栈仍需具备对应线路的独立实测；目前的三机 IPv4 验收不会将其计作已通过。

隔离 namespace 和 WSL 可达链路不能证明校园网 NAT4 已穿透。Windows 测试路径临时将 WSL 外层 MTU 从 1280 调为 1500，并在 finally 恢复；现有 1280 字节虚拟 MTU加外层开销需要更大的外层 MTU，不能把该实验环境的分片失败归因于 Phantun 本身。

所有必要项完成后，使用同一份已验收构建整体替换；任何必要项失败都继续修复，保留现行版本及回退资料。完整清单见 [PARITY.md](PARITY.md)。
