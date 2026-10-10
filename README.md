# StreamLink — Windows P2P 直连组网

通过自动映射与 udp2raw 为两台 Windows 提供虚拟 IP，重点改善特定 QoS 环境下的 UDP 传输。完整包内置所需组件，无需预装 Lucky、EasyTier、WSL、Python 或 .NET。业务数据始终由两端直传。

**0.3.0 预览版**重构为加入、创建、设置三页；新增 6 位限时配对码、加密邀请与双端校验、操作忙碌/成功/失败反馈、可选后台服务和托盘，以及独立协调服务。保留 0.2 已验证的原生 udp2raw 数据面。GUI 仍需管理员权限。

## 下载与使用

- [v0.3.0-preview Release](https://github.com/MrSGSA/StreamLink/releases/tag/v0.3.0-preview)：Windows 完整包、项目源码、校验文件、验证摘要。私有仓库下载需要登录有权限的 GitHub 账号。
- [使用说明](docs/初版使用说明.md)：服务器设置、6 位短码、服务/前台模式、升级与回退。
- [0.3 发布说明](docs/releases/v0.3.0-preview.md)、[验收记录](docs/releases/0.3-development.md)。
- [历史公网实测](docs/初版实测报告-20261010.md)、[来源与依赖](docs/来源与依赖.md)、[发布组件](docs/发布依赖说明.txt)。

两端解压完整包，管理员运行 StreamLink.exe，在设置中填写同一个自托管 HTTPS 协调地址。一端创建、另一端输入 6 位配对码点击加入；核对双方校验码后由创建端批准。实际直连成功后显示虚拟 IP 10.129.129.1 / .2。公共协调服务器尚未提供，界面保留选择占位。

首次运行不会自动安装服务。前台模式可驻留托盘；需要未登录自动连接时，在设置中明确安装后台服务。服务模式关闭界面后继续组网，点击停止网络才断开。

## 实现与边界

- WinDivert 原生 udp2raw 双端，FakeTCP + 明文 HTTP 特征；TCP STUN 持续保活、UPnP 短租约、成功入口记忆，也支持已有 Lucky 端点。
- TCP/UDP 可选，UDP 映射为实验模式。当前不是完整的通用 NAT 打洞框架，不保证双方严格对称 NAT 可连接。
- 保留固定 EasyTier 2.6.4 core/cli 负责本地虚拟网络，公网数据仅经 udp2raw。未集成 EasyTier Manager GUI。后续替换网络内核需要单独性能和兼容性验证。
- 6 位码仅定位 5 分钟临时房间；P-256 ECDH 公钥承诺、校验码核对和 AES-GCM 保护长期邀请。不是把 6 位数字当强加密密码，协议尚待独立安全审计。
- 协调服务仅保存身份槽位与加密端点公告，没有业务转发接口。现为自托管预览，未完成公共多租户运营能力。
- 当前每台设备一组双端配对，不是多人 Mesh；固定 10.129.129.0/24，冲突时拒绝启动。
- HTTP 特征不是 HTTPS。历史网络中纯 UDP 仍受约 6 Mbps 限制；不承诺任意环境永久绕过 QoS。

0.2 最终候选历史实测：50 Mbps、20 秒，104152/104152 包，49.99296 Mbps，零丢包，单次 RTT 采样约 15.4 ms。0.3 没有为测试中断现有连接，不能将历史成绩当成本版完整公网回归。全新系统、长期运行、冷启动及休眠换网仍需验证。

## 开发

Windows x64，.NET SDK 10、MinGW-w64 x64、CMake、Ninja；原生协议测试使用 Python 3。运行包不需要这些开发工具。

```powershell
.\scripts\Build.ps1 -Test
dotnet run --project tests/StreamLink.Tests -c Release
dotnet run --project tests/StreamLink.PairingTests -c Release
dotnet run --project tests/StreamLink.WindowsTests -c Release
.\scripts\Test-Coordination.ps1
.\scripts\Package.ps1 -EasyTierDirectory '已验证的 EasyTier 2.6.4 二进制目录'
```

WindowsTests 使用隔离配置目录，不注册真实服务、不更改生产网络。Test-Coordination 启动独立本地 HTTPS 测试服务，结束后停止。Package 校验签名驱动、生成每文件 SHA-256 清单并附依赖许可证与对应源码。Windows GUI/服务共用一套 .NET 10.0.12 运行时，CLI 保留在源码中，不再放入日常运行包。

协调服务部署见 [运维说明](docs/发现服务运维.txt)。Cloudflare Tunnel 的公网 HTTPS 可以指向同机 HTTP 回环源站；不要混淆这两段协议。

| 目录 | 内容 |
|---|---|
| src/StreamLink.Core | 映射、配对、质量测试与传输生命周期 |
| src/StreamLink.App | WinForms 界面、托盘与显式服务安装 |
| src/StreamLink.Service | 可复用前台/后台控制、持久配置、自动连接 |
| src/StreamLink.Discovery | 短码与加密端点协调服务 |
| transport/udp2raw | 固定 HTTP 分支及原生 Windows 移植 |
| tests / scripts | 回归、构建、打包及独立部署 |
| docs | 使用、证据、架构及后续工作 |

[产品与架构](docs/产品与架构.md)及[开发顺序与验收](docs/开发顺序与验收.md)保留产品蓝图，以本 README 和各版本验证摘要为已实现范围。
