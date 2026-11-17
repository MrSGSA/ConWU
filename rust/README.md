# ConWU Rust 迁移与替换验收

源码版本：`1.5.0`。完整验证范围见 [VALIDATION.md](VALIDATION.md)；对应安装包的三机升级与发布结果以 Release 随附的 `verification.json` 为准。

ConWU 自有核心、后台、配置存储、配对、发现、系统管理和更新逻辑已迁至 Rust，继续使用现有 HTML / CSS / JavaScript 界面。日常运行不启动 .NET；`compat/ConWU.DotnetOracle` 只用于开发时的协议对照。

第三方 FakeTCP C++ 承载、XDP C++ API 适配层、Wintun、WinDivert 和 Microsoft XDP 保留各自实现与许可。Windows Mimic 使用签名的 XDP 运行时和用户态 Rust 协议处理，没有 WinDivert 回退，也没有把协议栈放进 Windows 内核 eBPF。

## 构建身份

| 构建 | Windows 服务 | 数据目录与用途 |
| --- | --- | --- |
| 默认 | `ConWURustExperiment` | 独立实验，默认不能安装更新 |
| `--validation-instance <32位GUID>` | `StreamLink-Validation-<GUID>` | `%ProgramData%/ConWU-Validation/<GUID>`，用于 MSI 隔离验收 |
| `production,local-install` | 保留 `StreamLink-PersonalFeature` | `%ProgramData%/ConWU`，与旧资料目录分离 |

Linux 默认服务为 `conwu-rust-experiment.service`，正式构建保留 `streamlink.service`。`lab-api` 只开放测试用内存网卡注入，打包器拒绝交付带此 feature 的程序。`build-info` 可核对版本、产品身份、平台及 feature。

## 运行与迁移

在新的独立目录查看界面：

```text
conwu run --data <新的数据目录> --memory --no-tray
conwu status --data <数据目录>
conwu panel --data <数据目录>
conwu stop --data <数据目录>
```

真实组网去掉 `--memory`，需要管理员 / root 权限和对应组件。程序自动寻找旁边的 `components` 或 `app/components`，也支持 `--components`。WebUI 默认使用 loopback 随机端口、一次性入口票据和 CSRF。Windows 正常用户通过受限命名管道访问 SYSTEM 后台，不能读取后台私密资料。

```text
conwu migrate --from <旧资料目录> --data <新的独立目录>
```

导入仅读取旧资料，不启动网络、不注册服务、不更改开机启动。Windows 需要在原设备上解开 DPAPI；Linux 使用原资料的访问权限。不要同时启动原版和导入后的同一网络。导入保留设备及成员密钥、审批 / 撤销目录、订阅地址、PKARR 身份和序号、证书、协调记录与本机偏好。Windows 可用 `Audit-Migration.ps1`，Linux 可用 `audit-linux-migration.py` 核对。

当前公开的双机网络是迁移基线。已退役的直接 UDP、自动协议回退、旧短配对码和多成员治理不重新启用。历史源码中的端口预测、备用路径、UDP 探索等研究开关仍需独立迁移验证；遇到这些启用项会明确拒绝导入。

## 六协议

| 协议 | Windows | Linux |
| --- | --- | --- |
| TCP | 系统 socket、三连接分流 | 系统 socket、三连接分流 |
| HTTPS | rustls TLS + WebSocket、三连接分流 | 相同 |
| Phantun | Rust helper + WinDivert | Rust helper + raw socket |
| Mimic | Rust helper + Generic AF_XDP | Rust helper + AF_PACKET / raw socket |
| TCPRAW | 系统 TCP 握手 + Rust helper + WinDivert | 系统 TCP 握手 + Rust helper + raw socket |
| FakeTCP + HTTP | 独立 udp2raw 原生组件 | 独立 udp2raw 原生组件 |

Windows 使用官方 Wintun，Mimic 另需 Microsoft XDP 1.4.0。MSI 可安装随包签名运行时，普通实验启动不会安装驱动。Linux 使用 TUN，原始承载需要 `ip`、`nft` 和 raw socket 权限。TCP / HTTPS 支持 IPv6 外层和 36 位 IPv6 直连码，其余四种承载当前限 IPv4。

MSI 的 `install-xdp.ps1` 以驱动服务和网卡绑定判断是否需要安装，不能仅使用 `netcfg -q` 的退出码：组件未安装时该命令也可能返回 0。安装完成后检查驱动运行状态，修复活动网卡上被禁用的 XDP 绑定；不会回退到 WinDivert。已有入口设置按协议显示地址族范围，出码默认优先 IPv4，TCP / HTTPS 可显式选择 IPv6。

从 .NET 导入的 Windows 网络继续使用原有网卡所有权作用域、代次记录及类型，以便首次升级失败时原版仍可接回同一虚拟 IP；双方共享排他锁，不能同时运行同一网络。此兼容路径只读取和维护原有的网卡记录，不启动 .NET。

Wintun 每次使用新 GUID，按网络保存独占代次记录；只有确认属于本网络且 PnP 已移除的残留接口才可从路由检查中排除。Windows 类配置缓存尚未释放时，会执行可取消的等待及一次新 GUID 重试。网卡初始化不占住异步工作线程，面板可继续读取状态。

## 安装、更新与回退

更新先下载并核对 SHA-256，用户确认后由独立进程执行本地安装，安装阶段不依赖下载连接。GitHub 提供版本 / 摘要元数据；Gitee 使用相同 tag 的附件下载。因此 Gitee 目前不是独立元数据源。

Windows MSI 在覆盖程序前保存一份完整上一版程序、设置和原 MSI；成功后将当前完整 MSI 登记为维护源。`CONWU_MAINTENANCE_PATH` 可指定稳定的维护目录，本机发布优先使用 D 盘。相同 MSI 的维护不会覆盖已有上一版；失败安装由 MSI 与 SCM 事务恢复原文件和服务。

Linux 更新进程通过独立 systemd 单元运行，避免被原服务的进程组清理终止。安装后检查后台、启用网卡和协调监听；失败候选可退回上一版程序。回退不倒退已发布的 PKARR 序号和已签名撤销状态，完整旧设置另行保留。只保留当前版本与一份完整上一版，失败证据在恢复确认前保留。

Linux 正式包包含 `install.sh` / `uninstall.sh`，安装需要 Python 3 与 systemd。`sudo ./install.sh` 安装到 `/opt/conwu/current`，资料放在 `/var/lib/conwu`，沿用 `streamlink.service` 及 `conwu` / `streamlink` 命令。首次替换会只读导入 `/var/lib/streamlink`；保留完整旧程序、设置和服务定义。卸载保留资料。服务启动不强制等待 `network-online.target`，断网时由后台继续发现和重试。

Windows 自带更新成功路径及故障包回退、Linux systemd 更新成功与故障恢复均已通过隔离验证；最终候选仍以 [PARITY.md](PARITY.md) 为切换门槛。

## 开发构建

当前验收使用 Rust 1.95、MSVC / Windows SDK，以及 Linux musl 工具链。原生 FakeTCP 使用 CMake / C++。通用 Cargo 命令：

```text
cargo test --locked --manifest-path rust/Cargo.toml --workspace --all-features
cargo build --locked --release --manifest-path rust/Cargo.toml --package conwu --features local-install
cargo build --locked --release --manifest-path transport/phantun/Cargo.toml --workspace
```

正式候选增加 `production`，并先确定高于原正式版的稳定版本号。使用 `package.py --stage` 生成运行目录，再由 `Build-Msi.ps1` 构建 Windows MSI；WiX 固定为 6.0.2。Linux 正式交付使用静态 musl，并执行 `verify-linux-static.py`，避免开发机 glibc 版本高于服务器。

`dev.ps1`、`dev-linux.sh`、`build-linux-musl.sh` 是本工作机的工具链包装，路径和缓存位于 D 盘；其他机器应使用自己的工具链。不要把这些本机缓存路径当作运行依赖，不修改系统全局临时目录。

WSL 构建可通过 `CONWU_LINUX_TOOLCHAIN_ROOT`、`CONWU_LINUX_CARGO_HOME`、`CONWU_LINUX_TARGET_DIR`、`CONWU_LINUX_TMPDIR` 仅为当前进程指定原生文件系统上的工具链、缓存、产物及临时目录，避免 DrvFs 的大量小文件读写。正式打包拒绝未提交的源文件和构建输入，暂存目录必须是新的空目录，防止混入旧版本文件。

验证结果见 [VALIDATION.md](VALIDATION.md)，模块与边界见 [ARCHITECTURE.md](ARCHITECTURE.md)。

`python rust/test-web-presentation.py --app <候选程序>` 使用独立内存网卡后台及 Playwright 验证自动刷新下的概览、日志、输入框和弹窗文本选择，以及 IPv4 默认出码和显式 IPv6 出码。需预先安装 Python Playwright 与 Edge；测试不接触日用网络。`--source-assets` 只用于编译前检查工作区界面，正式验收不加此选项，以核对候选程序实际内嵌的界面。
