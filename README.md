# StreamLink — Windows P2P 直连组网

通过自动映射与 udp2raw 为 Windows 设备提供虚拟 IP，重点改善特定 QoS 环境下的 UDP 传输。完整包内置所需组件，无需预装 Lucky、EasyTier、WSL、Python 或 .NET。业务数据始终由设备间直传。

**当前开发分支为 0.4.1 原生多机预览版，已完成两台 Windows 的隔离公网测试。** 使用官方 Wintun 驱动和自主组网层，默认包不含 EasyTier；每网络最多 8 台设备，提供独立成员凭据、逐设备连接状态及按钮动效。两台现用设备仍保留 0.3.2，公网协调服务尚未升级。详见 [0.4 使用、验证与回退说明](docs/native-mesh-0.4.txt)。GUI 仍需管理员权限。

0.4.1 已将 TCP 入口与恢复优化接入实际运行路径：有总预算的 STUN 筛选、固定源端口复核与成功服务记忆，独立协调请求和本地恢复调度，以及新路径验证后才释放旧传输。参见 [本轮实现、验证及边界](docs/releases/v0.4.1-preview.txt)。没有新增业务中继，也没有宣称支持任意双 NAT4 的 TCP 同时打开。

打洞基础模块正在独立开发：同 socket UDP 检查、认证后学习真实来源和观测诊断已通过回环及 NAT 模型验证，尚未接入默认 udp2raw 路径；没有新增业务中继。参见 [打洞源码核对、验证与集成顺序](docs/traversal-foundation-20261011.txt)。

**下一阶段重点是严格 NAT 下的打洞效率与成功率，TCP / FakeTCP 优先。** 先补候选与双端尝试协商，再实验原生 FakeTCP 双主动握手，同时推进 UDP 同 socket 集成和有条件的预测/概率策略。现有传输吞吐转为阶段回归项目。实现次序及成功率、p50/p95、资源成本的验收见 [打洞研发目标](docs/traversal-roadmap-20261011.txt)；这些增强尚未发布。

对外技术讨论可使用[完整评审材料](docs/StreamLink-PRO技术评审材料-20261011.txt)，包含版本状态、功能原理、数据与控制路径、实测边界和待评审问题。

## 下载与使用

- [v0.3.2-preview Release](https://github.com/MrSGSA/StreamLink/releases/tag/v0.3.2-preview)：现有双机版本。0.4 候选由本分支构建，尚未替换 GitHub Release。私有仓库下载需要登录有权限的 GitHub 账号；[0.3.1](https://github.com/MrSGSA/StreamLink/releases/tag/v0.3.1-preview) 保留用于回退。
- [使用说明](docs/初版使用说明.md)：服务器设置、6 位短码、服务/前台模式、升级与回退。
- [0.3.2 连接优化与实测](docs/releases/v0.3.2-preview.md)、[后续演进与瓶颈分析](docs/演进路线与连接启动分析.md)、[0.3.1 滚动修复](docs/releases/v0.3.1-preview.md)、[0.3 验收记录](docs/releases/0.3-development.md)。
- [历史公网实测](docs/初版实测报告-20261010.md)、[来源与依赖](docs/来源与依赖.md)、[发布组件](docs/发布依赖说明.txt)。

0.4 需要支持 `meshProtocol:4` 的协调服务，继续兼容旧版公告与短码接口。设备解压完整包，管理员运行 StreamLink.exe，在设置中填写同一个自托管 HTTPS 协调地址。一端创建、其他设备逐台输入 6 位配对码点击加入；核对双方校验码后由创建端批准。新网段根据网络身份分配，界面显示各成员 IP。创建者可继续邀请或移除单个成员。公共协调服务器尚未提供，界面保留选择占位。

0.3.x 配对需要在双方升级后重新创建为 0.4 网络，轻量包不会自动迁移或恢复旧 EasyTier 后端。替换旧配对前会在本机受限配置目录保存 DPAPI 备份。不要单端升级现用连接；旧版说明中的固定 IP 与公网测速结果仅适用于旧版。

首次运行不会自动安装服务。前台模式可驻留托盘；需要未登录自动连接时，在设置中明确安装后台服务。服务模式关闭界面后继续组网，点击停止网络才断开。

## 实现与边界

- WinDivert 原生 udp2raw 双端，FakeTCP + 明文 HTTP 特征；TCP STUN 持续保活、UPnP 短租约、成功入口记忆，也支持已有 Lucky 端点。
- TCP/UDP 可选，UDP 映射为实验模式。当前不是完整的通用 NAT 打洞框架，不保证双方严格对称 NAT 可连接。
- 默认使用官方签名 Wintun 0.14.1 驱动，自主管理网卡、IPv4 数据报、成员认证、重放窗口和心跳。每台设备一张网卡，各设备对独立连接；连接变化不重建其他成员的网卡。旧 EasyTier 后端仅保留源码兼容路径，可通过 `-IncludeLegacy` 附带旧组件。
- 6 位码仅定位 5 分钟临时房间；P-256 ECDH 公钥承诺、校验码核对和 AES-GCM 保护长期邀请。不是把 6 位数字当强加密密码，协议尚待独立安全审计。
- 协调服务仅保存身份槽位与加密端点公告，没有业务转发接口。现为自托管预览，未完成公共多租户运营能力。
- 每台设备加入一个最多 8 成员的网络，IPv4 单播直连，不转发其他成员流量。A-B、A-C 可连不意味着 B-C 能连。成员证书和目录由创建者签名，各链路采用 ECDH/HKDF/AES-GCM；长期身份密钥暂不提供前向保密。广播、多播及 IPv6 尚不支持。
- HTTP 特征不是 HTTPS。历史网络中纯 UDP 仍受约 6 Mbps 限制；不承诺任意环境永久绕过 QoS。

0.4 本地验证覆盖三节点路由、udp2raw FakeTCP + HTTP 多客户端回环、真实 Wintun 与 Windows UDP socket 往返、独立 HTTPS 协调服务，以及旧配对、服务生命周期和高 DPI 渲染回归。2026-10-11 的 0.4.1 双端公网测试中，两个方向分别发送 50 Mbps、20 秒，收到 49.997 / 49.979 Mbps，均零丢包；负载期间 24 次 ping 为 13–15 ms、零丢包。单个传输进程退出后首次 ping 成功为 5.271 秒，之后短暂仍有超时；完整测试进程重启建连为 18.891 秒。详情及测量边界见 [双端实测报告](docs/wan-test-0.4.1-20261011.txt)。第三台真实设备、长时间串流、系统冷启动和休眠换网仍待实测。

历史 0.3.2 双端实测：50 Mbps、20 秒，104142/104142 包，49.98816 Mbps，零丢包，单次 RTT 14.95 ms。单端服务重启从 56.259 秒到 52.343 秒（各一次），改善有限。上述结果不可沿用为 0.4 成绩。

## 开发

Windows x64，.NET SDK 10、MinGW-w64 x64、CMake、Ninja；原生协议测试使用 Python 3。运行包不需要这些开发工具。

```powershell
.\scripts\Build.ps1 -Test
dotnet run --project tests/StreamLink.Tests -c Release
dotnet run --project tests/StreamLink.PairingTests -c Release
dotnet run --project tests/StreamLink.WindowsTests -c Release
dotnet run --project tests/StreamLink.ConnectionTests -c Release
dotnet run --project tests/StreamLink.MappingTests -c Release
dotnet run --project tests/StreamLink.MeshTests -c Release
dotnet run --project tests/StreamLink.TraversalTests -c Release
dotnet run --project tests/StreamLink.MeshTests -c Release -- --raw out/native/udp2raw-protocol-test.exe
.\scripts\Test-Coordination.ps1
.\scripts\Package.ps1
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
| transport/tun | Wintun 与 Windows IP Helper 原生桥接 |
| tests / scripts | 回归、构建、打包及独立部署 |
| docs | 使用、证据、架构及后续工作 |

[产品与架构](docs/产品与架构.md)及[开发顺序与验收](docs/开发顺序与验收.md)保留产品蓝图，以本 README 和各版本验证摘要为已实现范围。
