# ConWU Rust 重写实验

实验分支：`experiment/rust-rewrite`。版本：`1.4.5-rust.1`。

本分支把 ConWU 的自有核心和后台迁至 Rust，包含配置存储、配对与身份、加密数据通道、多网络管理、发现与协调、WebUI 后台、平台服务、日志、更新检测和 UU 接管。产品运行不启动 .NET；`compat/ConWU.DotnetOracle` 只参与开发时的双向协议对照测试。

现有 HTML/CSS/JavaScript 界面继续使用。第三方 FakeTCP C++ 承载、XDP C++ API 适配层，以及 Wintun、WinDivert、Microsoft XDP 系统组件保留各自实现与许可。本实验没有把系统驱动改写为 Rust，也没有把 Windows Mimic 变成内核中的 eBPF 协议栈。

本轮没有部署到笔记本、台式机或服务器，没有发布或推送到 GitHub/Gitee。原工作区及其未提交修改保持独立。

## 本地产物

`out/rust-experiment/` 保存 Windows x64 ZIP、Linux x86_64 tar.gz、源码快照、文件校验和及测试证据。二进制均为默认 feature 构建：没有实验注入 API，也不能执行本地更新安装。Linux 包在本地 Arch Linux / WSL 构建，其 glibc 要求见包内构建信息，未视为正式服务器通用包。

## 运行与停止

先使用内存网卡查看界面，不创建真实网卡：

```powershell
.\conwu.exe run --data D:\ConWU-Rust-Test\data --memory
.\conwu.exe panel --data D:\ConWU-Rust-Test\data
.\conwu.exe stop --data D:\ConWU-Rust-Test\data
```

Linux：

```bash
./conwu run --data "$PWD/experiment-data" --memory --no-tray
./conwu panel --data "$PWD/experiment-data"
./conwu stop --data "$PWD/experiment-data"
```

`--data` 必须指向新的空目录或已有 `.conwu-rust-owned` 标识的实验目录。不要指向正式版目录。后台只监听 loopback 的随机端口，启动输出一次性 WebUI 链接；后续用 `panel` 获取新链接。日志、身份、证书和更新资料均写入这个数据目录。

真实组网使用相同命令去掉 `--memory`，需要对应管理员权限及组件。组件默认位于程序旁的 `components/`，也可用 `--components` 指定。

| 协议 | Windows | Linux |
| --- | --- | --- |
| TCP | 原生 socket | 原生 socket |
| HTTPS | rustls TLS + WebSocket | rustls TLS + WebSocket |
| Phantun | Rust helper + WinDivert | Rust helper + AF_PACKET/raw socket |
| Mimic | Rust helper + Generic AF_XDP，纯 XDP，无 WinDivert 回退 | Rust helper + AF_PACKET/raw socket |
| TCPRAW | 系统 TCP 握手 + Rust helper + WinDivert | 系统 TCP 握手 + Rust helper + raw socket |
| FakeTCP + HTTP | 独立 udp2raw 原生组件 | 独立 udp2raw 原生组件 |

Windows 的虚拟网络使用官方 Wintun；Mimic 需要机器预先安装兼容的 Microsoft XDP 1.4.0 运行时。实验启动不自动安装或替换 XDP。Linux 使用临时 TUN，原始承载依赖 `ip`、`nft` 和 raw socket 权限。

## 已有设置的只读导入

```powershell
.\conwu.exe migrate --from D:\Old-ConWU-Data --data D:\ConWU-Rust-Test\imported
```

源与输出目录必须完全独立。导入仅读取旧资料，不启动网络、不注册服务、不改变开机启动。支持当前主从双机身份与独立网络设置；旧多成员、equal governance 及 SL5 网络会明确拒绝。当前平台需要能解开旧资料原有的保护。Windows 可导入本机旧 DPAPI 资料，不能绕过另一台设备或账号的保护。

本轮已验证 TCP 身份与设置导入，以及由 .NET 生成的临时 HTTPS PFX 导入，导入后保留已批准的 SPKI。没有对生产资料执行迁移；正式切换前仍需真实旧资料与恢复演练。

## 构建

Rust stable（edition 2024）、C/C++ 工具链、Python 3。Windows 主程序使用 MSVC 和 Windows SDK；资源编译器位置可通过 `CONWU_RC` 指定。FakeTCP 组件使用 CMake + MinGW-w64；其他两个 helper 使用 MSVC。

```text
cargo build --locked --release --manifest-path rust/Cargo.toml --workspace
cargo build --locked --release --manifest-path transport/phantun/Cargo.toml --workspace
cmake -S . -B out/native -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build out/native --target udp2raw-native
```

两个 Cargo workspace 的 target-dir 需要统一到 `out/rust-target`，或给打包脚本指定实际目录。根 `.cargo/config.toml` 已为本实验设置默认路径和 Windows 静态 CRT。

`dev.ps1`、`test-linux.sh` 和 `build-native-lab.sh` 是本工作机的辅助脚本，工具链和缓存路径在 D 盘，不应当作其他电脑的安装器。通用环境直接运行上述 Cargo 命令；临时目录和依赖缓存通过进程环境配置即可，无需修改系统全局环境变量。

```powershell
& ./rust/dev.ps1 -CargoArguments @('test','--offline','--manifest-path','rust/Cargo.toml','--workspace','--all-features')
python rust/ui-smoke.py
python rust/package.py --platform windows --dependency-root ../ConWU-Converged/out/dependency-cache
python rust/package.py --platform linux
```

`lab-api` 只用于临时测试后台；`local-install` 只保留后续安装开发入口。它们均默认关闭，交付包保持关闭。本轮没有制作或执行 Rust MSI，没有验收安装后自动恢复的完整生命周期。

## 当前完成度

本轮已具备可运行的 Rust 桌面后台和六协议数据链路，不等于正式版已经可以无条件替换。主路径、验证范围及遗留差异见 [验证与差异](VALIDATION.md)，内部模块见 [架构](ARCHITECTURE.md)。

尤其需要继续验证 Windows 实际驱动链路、真实 UU 串流、长期重启与网卡切换、严苛 NAT、真实 PKARR 网关，以及旧安装升级恢复。旧版 native simultaneous-open capture broker、RejoinProof / EntryAdmission 和全部历史研究 API 尚未实现逐项等价；当前主流程采用直连码与 SAS 审批。
