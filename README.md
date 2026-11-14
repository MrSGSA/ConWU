# ConWU

当你异地串流美美游戏却碰上 UDP 限速时，可以试试ConWU。它在两台设备间建立直连通道，通过TCP打洞以及FakeTCP+HTTP(UDP2RAW）、Phantun、mimic、tcpraw、HTTPS与TCP等协议来规避运营商对UDP的限制！目前支持 Windows 和 Linux 双端。

首次连接只需分享 16 位直连码，由主机批准。从机会自动获取网络设置，之后继续发现和更新入口。

[下载最新版](https://github.com/MrSGSA/ConWU/releases/latest) · [版本说明](docs/releases/1.4.2.md) · [使用文档](docs/README.md)

| 系统 | 下载与安装 |
| --- | --- |
| Windows x64 | 下载 Release 中的 `.msi`，安装后从托盘打开 WebUI |
| Linux x86_64 / glibc | 下载 `.tar.gz`，解压后执行 `sudo ./install.sh`；提供 WebUI 和 CLI |

Android 从机已进入本地测试，支持纯 TCP 与 HTTPS，见[Android 测试版说明](docs/Android使用.md)。尚未发布 Android 正式附件或完成真机串流验收；iOS 暂待构建条件。

## 怎么连接

1. 主机打开“创建网络”，填写名称和网络设置，生成直连码。
2. 另一台设备在“加入网络”输入直连码，核对双方校验码，由主机批准。
3. 直连成功后，把对方的虚拟 IP 填入 Moonlight 等串流软件。

直连码显示为 `XXXX-XXXX-XXXX-XXXX`，不区分大小写，有效五分钟。

## 选哪种入口

- **自主打洞**：默认配合 PKARR 自动发布和查询最新地址，无需额外的协调服务器或DDNS域名。若希望自行掌控发现服务时，可在高级选项中使用自己的 HTTPS 协调服务器。
- **已有入口**：填写公网地址、路由器转发、第三方工具打通的地址或 HTTPS/TXT 订阅。后续自动查询保存的订阅；静态地址（非订阅可自主更新的地址）变化时需要重新生成直连码并填写。多主机订阅可用 `#streamlink1` 等标签区分不同主机的地址（如streamlink1=xxx.xxx.xxx.xx1 streamlink2=xxx.xxx.xxx.xx2）。

每个网络一主一从、通道双向。同一设备可以同时创建和加入多个网络.

## 功能说明

实际效果取决于两端 NAT 和实际限速策略，ConWU 不保证所有网络都能打通，也很难保证在复杂的限速策略下都有用。

目前提供的协议如下:FakeTCP+HTTP(UDP2RAW),Phantun,Mimic,TCPRAW,TCP,HTTPS。实际效果由用户自行测试。

自主打洞优先尝试短期 UPnP 映射，处理外部端口占用与续租；端口设置中可选 PCP／NAT-PMP 后备。已有入口模式不申请映射或启动另一套打洞。路由器的 NAT1 等功能仍由用户设置，网关授权或 STUN 候选均需对端认证验证。

TCP／HTTPS 自主入口复用独立探测端口的网关映射。多网络可分别选择、生成和复制直连码，设置错误显示在当前浮窗。Windows／Linux 设置页支持更新检测，Linux 也可运行 `conwu update check`。

Windows 左侧“UU远程”提供默认关闭的接管开关。已有 ConWU 网络直连后，开启接管并重新连接 UU 会话（成功后UU远程统计信息会显示UDP LAN），软件自动匹配已直连网络；主从机只需一端开启或两端均开启本功能；

本版为纯 TCP 和 HTTPS 提供可选的“按流分离连接”，在网络设置的“连接方式”中开启。不同流使用独立连接，同一流保持顺序；不增加网络或重新配对，对端不支持时使用单连接。默认关闭。



## 开发与许可

使用 .NET 10、Rust、CMake 和 MinGW-w64，见[开发说明](docs/开发说明.md)。网络模型与后续方向见[产品与架构](docs/产品与架构.md)和[后续计划](docs/后续计划.md)。

主程序使用 [MIT 许可证](LICENSE)。可选的 Mimic/TCPRAW 原生进程使用 GPL-2.0-only，其源码和构建依赖随包提供；其他第三方组件遵循各自许可证。
