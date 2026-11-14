# Android 从机测试版

Android 先行，iOS 暂待 Mac、Xcode 与签名条件。当前为本地测试版，与桌面本轮一起构建，不上传正式 Release。

## 安装与连接

支持 Android 8.0（API 26）及以上，提供 ARM64 与 x86_64 通用 APK；首轮系统验证使用 Android 15 x86_64 模拟器，尚未完成物理手机及 Moonlight 串流验收。

模拟器已通过 TCP／HTTPS 审批与校验码核对、双网络虚拟 IP 通信、真实 UDP 套接字二进制回声、应用进程重开恢复，以及同签名 APK 覆盖安装保留凭据。地址适配另外覆盖 TCP／UDP 校验和、IPv4 分片及 ICMP 错误引用报文。

1. 安装测试 APK；手机需允许当前来源安装应用。
2. Windows 或 Linux 主机创建专用于手机的网络，协议选“纯 TCP”或“HTTPS”，准备可达的 TCP 入口并生成 16 位直连码。现有 1.3.1 主机可使用这两种协议。
3. 在手机输入直连码并请求加入，允许系统 VPN 授权，核对双方校验码，由主机批准。主机审批后自动继承配置，不需要手机重复填写入口。
4. 手机显示已直连后，将“主机虚拟 IP”填入原版 Moonlight。Sunshine 与 Moonlight 的自身配对仍按原流程操作。

手机提供加入、连接、重试、断开、退出、日志、更新及配合主机的 UU 接管，不创建网络或提供协调服务。手机仅支持 TCP 与 HTTPS；FakeTCP、Phantun、Mimic、TCPRAW 和直接 UDP 会明确提示不支持，不自动改用其他协议。主机的多个逻辑网络使用独立身份和虚拟地址，手机合并为一个系统 VPN。

## 恢复与配置

- 主机下发的已有入口订阅、PKARR 或可选协调发现用于后续刷新地址；仅使用静态直连地址时，地址变化后无法凭身份自动找到新地址。
- 自主打洞获得的 STUN 地址是候选，不能保证主机允许异地 TCP 入站。首次请求超时会区分 TCP 入口、HTTPS 握手、通道协商和配对码阶段；入口不可达时应核对公网映射，或由主机使用可达的已有入口。PKARR 的地址发现不会改变 NAT 的入站限制。
- 配对凭据由 Android Keystore 加密保存，并排除系统备份。应用重开时恢复已启用网络；断开操作保留凭据，退出网络移除本机记录。主机授权需要在主机端另行撤销。
- Wi-Fi／蜂窝等系统网络变更会触发入口刷新和重新连接。主机入口是否可达、移动运营商限制、IPv6-only／NAT64 和各厂商省电策略仍需真机验证。
- 仅已批准的主机虚拟 IP 进入 VPN，普通互联网流量维持原路由。ConWU 自身的承载与发现连接绕过 VPN。Android 通常只能同时使用一个普通 VPN，与其他 VPN／代理应用并用需另行确认。
- 前台通知显示 VPN 连接状态。系统回收后允许恢复；用户强制停止后需手动重开应用。锁屏、后台切到 Moonlight及长时间串流仍待实测。
- 配置损坏或密钥不可用时保留原文件并给出错误，不自动清空或重置网络身份。

测试 APK 使用本机构建环境的 **Android SDK 开发签名**。同一签名且 versionCode 不降低时可覆盖安装并保留凭据；正式签名尚未确立，未来切换签名可能需要卸载并重新配对。不要把这个 APK 当作已经完成正式签名和手机验收的发行版。

## 软件更新

Windows、Linux WebUI 的设置页和 Android 提供“检查更新”；Linux 也可执行 `conwu update check`，无需后台先启动。只查询官方 GitHub 正式 Release，按平台及 CPU 架构选择附件，不发送网络身份或配对凭据。当前不查询预览版渠道；没有 Android 附件时不会下载桌面包代替。

Windows 安装版可下载完整 MSI，校验后由用户确认，由独立本机更新程序继续安装并恢复后台及已启用网络。Android 可在应用内下载完整 APK，核对哈希、应用身份、版本号和签名后交给系统安装；需要系统允许 ConWU 安装应用并确认，不能静默绕过 Android 的要求。覆盖安装保留 Keystore 与网络，系统包替换通知会尝试恢复 VPN；厂商限制后台启动时需打开 ConWU。Linux 仍由用户部署下载包。

## UU 远程接管

先在 Windows 主机开启“UU 远程接管”，再连接手机 ConWU 网络并重连 UU 会话。Android 页面的开关保留在本机，所有已直连网络自动参与，按 UU 选择的目标设备通信，不需要选网络。Android 10 及以上使用系统连接归属接口，仅将属于 `com.netease.uuremote` 且确实通过 VPN 的流量统计为 UU；其他版本不宣称已按应用核验。

Windows 使用已验证的临时套接字规则，Android 配合主机并使用现有系统 VPN，不提供 root hook 或独立替换 UU 的信令。手机上“VPN 已就绪”不代表 UU 已经走 ConWU，必须看到实际 UU 流量；没有经过手机实测前，不宣称 UU Android 串流接管完成。UU 终端、文件和端口转发不在本轮验收范围。

## 构建

需要 .NET SDK 10、Android workload、Android SDK 36 和兼容 JDK。本轮验证环境使用 JDK 17；工具链由构建机器准备，不随 APK 分发。

```powershell
dotnet workload install android
./scripts/Build-Android.ps1 -AndroidSdkDirectory D:/Android/sdk `
  -JavaSdkDirectory D:/Java/jdk -DevelopmentSigning
```

脚本生成 Release 配置的测试 APK、SHA256 和包信息；不修改三机生产服务。后续更新必须保留相同签名并递增 versionCode。正式分发需要单独管理私有签名文件和凭据。

核心回归：`dotnet run --project tests/ConWU.MobileTests -c Release -p:StreamLinkPersonalFeature=true`。`scripts/Test-AndroidClient.py` 仅运行于隔离的 `emulator-5580`、ADB 5038，并先验证为模拟器；它清空的仅是该模拟器的 ConWU 测试数据。系统测试使用临时 TCP／HTTPS 主机和真实系统 VPN，不修改已安装桌面服务。
