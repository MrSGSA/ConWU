# PF2 自研 TUN 实验与目标准入

本文件只覆盖 702ee2e 审查中的 PF2-04，不取代个人 v3 规格。已有真实 miniport、用户 DLL、产品工厂和准入守卫继续使用。未经实测，不把代码、签名或模板标记成内核通过。

## 实验来宾

2026-10-15 Thinkbook 只读检查：32 GB RAM，D: 约 334 GiB 空闲，HypervisorPresent=true，vmms 与 VMware 授权服务运行；Get-VM 没有现成来宾。WMI 在已有 hypervisor 下的 SLAT/固件布尔值不作为不支持虚拟化的证明。准备一个 2 vCPU、4–6 GB RAM、60 GB 磁盘的 Windows x64 来宾在资源上可行；尚未创建、启动或验证快照恢复。还缺 Windows 来宾介质/许可、创建授权、可恢复快照及测试签名环境。

建议 Hyper-V 第二代独立来宾、私有或默认 NAT 虚拟交换机、控制台恢复入口；不要为了此实验改 VMware 桥接或日用宿主网络。先验证还原检查点能启动，再在明确获授权的来宾安排调试、测试签名和定向 Verifier。**本轮没有创建 VM、导入证书、开启测试签名、关闭安全启动/HVCI、安装研究 SYS 或启动宿主 Verifier。**

微软的目标机流程允许 VM，但目标机测试签名涉及来宾安全策略；这不授权改宿主。[目标机配置](https://learn.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/provision-a-target-computer)。日用 Windows 的加载签名另需符合其实际策略。[签名要求](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-requirements--windows-vista-and-later-)。

## 先签名，再固定身份

由具备证书及授权的人完成实验包签名。日用目标的可接受签名须独立取得，来宾测试证书不能代替微软生产加载签名。签名必须覆盖实际 SYS/INF 的 CAT 成员，并用 WDK signtool 的内核策略和 catalog membership 检查核验。完成后运行 `Freeze-SignedTunPackage.ps1 -Package <签名目录>`，审核确认后重新固定 package-identity；旧 unsigned 身份/批准失效。发布运行包 manifest 也需重建。

`Manage-PersonalTun.ps1 -Action InstallLab` 仍要求明确的可恢复实验授权、恢复确认、已信任 CAT 和微软签名的 WDK DevCon；不自动改变系统策略。只安装一个 ROOT\StreamLinkTun 实例。保留精确设备实例、驱动版本、SetupAPI/CodeIntegrity 日志和恢复点。

## 真内核工具

Windows 包根目录的 `StreamLink.TunKernelTests.exe`（研究 ZIP 中为独立 `tun-kernel-probe/`）使用实际研究设备上的重叠 READ/WRITE/IOCTL、OS UDP 与 NDIS，不通过内存适配器或研究委托模型。默认没有自动加载入口。仅 `--contract-test <新结果>` 不打开设备。

实际运行仅在独立来宾，已签名并加载的精确设备上：

```powershell
./Invoke-PersonalTunKernel.ps1 -Package <已签名固定包> `
  -Probe <工具.exe> -HostMachineGuid <日用宿主身份> `
  -DeviceInstance 'ROOT\STREAMLINKTUN\0000' `
  -AuthorizedRecoverableLab -RecoveryConfirmed
```

脚本对真实 VM 型号/机器身份、已加载镜像 hash、唯一设备及空闲实验网段做前置检查。只给选定实验接口添加临时 10.254.242.1/24，退出后移除自己添加的地址；不配置默认路由或转发。结果保存在管理员/SYSTEM 专属 ProgramData\StreamLink-TunLab\RunId。90 秒进程外 watchdog 仅终止本次子进程，挂起 IRP 的缓冲和 OVERLAPPED 在确认完成前不释放。

工具要求十次 1280B 内层包的 OS→NDIS→READ 与 WRITE→NDIS→OS、30 次真实取消/送包竞争、最多 16 个实际待完成 READ 的取消、内核统计归零、关闭及重开。记录实际取消计数；没有真实 CSQ pending 就不算取消覆盖。用户态唯一观察不等于已证明内核绝无双完成，须结合定向 Verifier 和崩溃/转储证据。

权限负例在**同一来宾**的标准用户下执行 `--permission-check <lab-plan.json> <结果>`。仅 ERROR_ACCESS_DENIED 接受，缺设备不算通过。计划应只读提供给标准用户；将其真实输出由管理员复核后导入受保护证据目录。不要把标准用户目录中的可变文件直接当批准依据。

定向 Verifier 的启用/重启需另行授权并只限来宾的 StreamLinkTun.sys。不要使用 `/all`。已启用且重启后重新跑内核测试，脚本记录前后实际 `/query` 和 `/querysettings`。`Collect-PersonalTunVerifier.ps1 -RunRoot <本次目录> -OperatorReviewed` 采集运行状态、当前启动周期系统 BugCheck 和 CodeIntegrity 记录；操作人须审阅设置、NDIS/IRQL、转储及错误，不因文件存在就通过。

## Gate 与本人目标

`Complete-PersonalTunGate.ps1` 只接受同一个固定包/来宾/RunId 的内核、标准用户拒绝、实际 Verifier 和受保护原始文件 hash；模板、缺文件、旧 hash 或非管理员可写证据被拒绝。默认只发行 kernel-gate。只有明确 `-AuthorizeTarget`、精确目标机器及设备身份才创建短期 target-approval。管理员发行是信任决定，hash 不是第三方认证或证据防伪。

产品继续检查固定 Program Files 路径、ACL、CAT 信任、实际加载 SYS、目标 PnP/接口和当前批准。VM Gate **不证明宿主自研 TUN 已运行**。两个日用宿主各需可接受签名、自己的加载授权和目标适配证据；其后才能先 C2 一端替换、再 C3 双端替换，验证完整 FakeTCP/Wintun 的对应业务对照及回退。当前工具编译/拒绝分支可以验证，实际 IRP/NDIS/电源/PnP/Verifier 与 C2/C3 在缺来宾或签名时明确 BlockedExternal，不宣布本人完整目标通过。
