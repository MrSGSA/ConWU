# 个人 v3 自研 TUN 准入与恢复

这是 ROOT\StreamLinkTun 原生 NDIS miniport；不是 Wintun 的改名封装。产品 descriptor ABI=2；SLT_UserApi 和 IOCTL ABI=1。

完整包包含实际 SYS、INF、Inf2Cat 生成的 CAT、用户 DLL、托管 provider 和包身份。生成 CAT、编译及用户态无效句柄测试不证明内核安全。当前 CAT/SYS 未签名，没有可恢复实验机，实际内核 I/O/Verifier/两台日用机加载均为 BlockedExternal。

`Manage-PersonalTun.ps1 -Package <完整包>/components/self-tun` 默认只读，显示包哈希、签名、实际 PnP 实例与加载状态；不创建设备。安装步骤只在明确授权并已有恢复镜像/控制台的实验机运行：

```powershell
./Manage-PersonalTun.ps1 -Action InstallLab -Package <冻结签名包> -DevCon <微软WDK/devcon.exe> -AuthorizedRecoverableLab -RecoveryConfirmed
```

必须先取得适用的签名。脚本拒绝未信任 CAT，不启用测试签名，不关 Secure Boot/HVCI，不安装根证书，不自动重启。只添加 INF 不能代替 root 设备创建。

实验机依次验证：完整 1280B IPv4 双向用户 DLL→IRP→NDIS，ABI/真实 LUID/index/计数；64 次可证明的预取消/排队取消与 30 次竞争；唯一完成/配额归还；停止、清理、进程退出、PnP、休眠与定向 Verifier。保留逐项 DriverKernelIO 原始记录及失败。仅用户态测试不能填内核列。

内核 Gate 后，由管理员审查并在目标机的受保护 `%ProgramData%/StreamLink-PersonalFeature/tun-admission` 保存 `kernel-gate.json` 与 `target-approval.json`。模板见 `tun-admission-template.json`；模板包含 NotTested，不能直接取得准入。批准绑定本机 MachineGuid、当前 package-identity.json 哈希、准确设备实例、内核证据哈希及最长 90 天有效期。产品还检查实际加载映像 SHA256、签名及唯一设备；不得仅靠 index、DLL 路径或 boolean 开放。

在各目标日用机加载前分别授权并核验恢复路径；不得依赖新网卡承担唯一 SSH 管理。首次加载应有本地/离线恢复，应用无法对内核蓝屏承诺热回退。不存在可用准入时选择自研 TUN 会明确失败并保留当前连接，绝不偷偷使用 Wintun 后显示“自研已启用”。

实验机撤回：先停止个人实例，再对准确实例运行 RemoveLab（同样需要授权/确认）；脚本不卸载共享 Wintun/WinDivert，不清理无关映射/旧配置。日用机仍以独立 0.3.2 为回退。
