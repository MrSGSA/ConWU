# StreamLink — Windows P2P 直连组网

通过自动打洞与 udp2raw 建立通用虚拟网络，重点改善特定 QoS 环境下的 UDP 传输。软件提供虚拟 IP、P2P 状态和链路质量，组网后使用什么应用由用户决定。完整包内置所需组件，不用预装 Lucky、EasyTier、WSL、Python 或 .NET。

**当前 0.2.0 预览版**：持久配对、自动入口选择与成功方向记忆、可编辑 STUN 列表、Windows 后台服务、公网发现服务和端点更新已经完成双端联调。关闭 GUI 继续组网，服务在 Session 0 运行。首次仍需传递长邀请，当前 GUI 需要管理员权限。

0.2.0 最终候选实测：50 Mbps、20 秒收到 **104152/104152 包，49.99296 Mbps，零丢包**；最终连接状态采样 RTT 约 15.4 ms（不是全程延迟统计）。发现服务停机时 P2P ping 20/20 成功。详见实测报告与发布包内的验证摘要。

历史 0.1.0 实测：Akane → Thinkbook 完整链路 50 Mbps 连续 180 秒收到 937435/937435 包，平均 49.996 Mbps，RTT 中位数 18.39 ms。普通 UDP 和 STUN/TURN 形态实验仍约 6 Mbps，尚未绕过这条路径的限制。0.1.1 保持传输内核不变，历史公网数据不冒充新版本重测。

## 使用和证据

- [初版使用说明](docs/初版使用说明.md)：双端启动、邀请、虚拟 IP、NAT 要求及回退。
- [本轮实测报告](docs/初版实测报告-20261010.md)：测量、实现、失败实验和边界。
- [来源与依赖](docs/来源与依赖.md)、[发布组件](docs/发布依赖说明.txt)：固定版本、许可证和源码。
- [下载 Windows x64 完整包](https://github.com/MrSGSA/StreamLink/releases/download/v0.2.0-preview/StreamLink-0.2.0-win-x64-preview.zip)：解压后以管理员权限运行 `StreamLink.exe`，首次操作安装后台服务。
- [下载本项目源码包](https://github.com/MrSGSA/StreamLink/releases/download/v0.2.0-preview/StreamLink-0.2.0-source.zip)：源码、构建脚本及测试；运行包内 `sources` 另含 EasyTier 和 WinDivert 对应版本源码。
- [v0.2.0-preview Release](https://github.com/MrSGSA/StreamLink/releases/tag/v0.2.0-preview)：发布说明、SHA-256 校验文件和最终验证摘要。私有仓库的下载需要登录有权限的 GitHub 账号。

这是可运行的预览版，尚未完成干净 Windows 驱动首次安装、长期游戏、晚高峰、休眠换网和各种路由器验证。HTTP 特征不是 HTTPS；域名对 QoS 分类的因果作用没有被证明。不承诺所有 NAT 都能打洞或永久绕过限速。

## 当前实现

- WinDivert 原生 udp2raw 客户端和服务端，IPv4 FakeTCP/UDP；不引入标准 TCP 有序重传。
- 自研 STUN TCP 持续保活、UPnP 短租约、规则所有权检查；不依赖 Lucky 程序。保留已有 Lucky 端点入口。
- 内置固定 EasyTier 2.6.4，公网只经 udp2raw；没有业务中继或静默 TCP 回退。
- 中文 WinForms、长邀请配对、双方虚拟 IP、连接状态、任一端可发起的 20 秒 50 Mbps 测试、日志、退出清理和崩溃后恢复。
- 两端临时地址 10.129.129.1 / .2；支持一对设备，不是多人 Mesh。使用长邀请加自托管发现服务及持久配对，尚无六位短码、账户体系、自动升级或多节点 Mesh。

## 开发

Windows x64，.NET SDK 10、MinGW-w64 x64、CMake、Ninja；协议测试需 Python 3。用户运行包不需要这些开发依赖。

```powershell
.\scripts\Build.ps1 -Test
dotnet run --project tests/StreamLink.Tests -c Release
.\scripts\Package.ps1 -EasyTierDirectory '已验证的 EasyTier 2.6.4 二进制目录'
```

打包脚本验证驱动签名、保留依赖许可证、产生每文件 SHA256 清单和源码包。自包含运行时为本次验证的 .NET 10.0.12。首次打包下载官方 WinDivert/Wintun 和固定 EasyTier 源码，需联网。

`udp2raw-protocol-test.exe` 仅为回环协议替身，不能验证公网 QoS，打包时排除。正式 `udp2raw-native.exe --native-info` 不加载驱动；运行会话由控制器显式允许按需加载官方签名驱动。本次复用两端已有驱动，未升级或卸载它们。

| 目录 | 内容 |
|---|---|
| `src/StreamLink.Core` | 映射、邀请、进程/网卡生命周期、质量测试 |
| `src/StreamLink.App` / `StreamLink.Cli` | 中文桌面程序和自动验证入口 |
| `transport/udp2raw` | 固定 HTTP 分支及原生 Windows 移植 |
| `src/StreamLink.Service` | Windows 服务、持久配置及自动连接 |
| `src/StreamLink.Discovery` | 可自托管的加密元数据发现服务 |
| `tests` | 9 项历史传输回归；35 项核心校验，另有 5 项公网发现和 12 项真实服务检查 |
| `scripts` | 编译与完整发布打包 |
| `docs` | 用户说明、证据、架构和后续工作 |
| `out` / `artifacts` | 本地构建、发布包及测试输出 |

[产品与架构](docs/产品与架构.md)和[开发顺序与验收](docs/开发顺序与验收.md)包含后续产品蓝图；以本 README 与当日实测报告为已实现范围。原有验证包及生产网络保持独立。

关闭界面后后台服务继续运行；要断开连接，请点击“停止网络”。版本更新前先停止旧版本，保留需要回退的旧包及其说明。
