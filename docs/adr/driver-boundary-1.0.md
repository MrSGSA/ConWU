# ADR：自研 TUN 研究边界（DRV-00/01）

采用原创 NDIS 6.30 raw IPv4 miniport，`NdisMediumIP`、1280B MTU、点对点虚拟接口；不以虚拟以太网样例改名后宣称 TUN，也不在内核实现 NAT、加密或 udp2raw。内核只处理 OS 与用户态间的 L3 数据包。包头长度、总长度与 IPv4 版本有界；不支持 IPv6、卸载、共享 ring、任意内核地址或通用读写 IOCTL。

默认继续官方 Wintun，研究程序集没有被 App/Service 引用，生产 provider 白名单继续拒绝 `streamlink-tun-experimental`。研究构造需明确 admission、管理员权限、已存在的研究接口；不能自动装驱动或回退打开其他网卡。官方适配器 ABI2 不变；研究内核/用户DLL独立 ABI1，研究 provider 映射到现有 IPacketAdapter ABI2。

源码：`drivers/StreamLink.Tun/{driver.c,abi.h,StreamLinkTun.inf}`、`transport/tun-native/user_api.*`、`src/StreamLink.ResearchAdapters/`。MIT 原创实现。参考的是公开 NDIS/WDM API；未复制 Wintun 内核、共享 ring 或驱动安装器。INF 的 NDIS 介质/绑定值属于 Windows ABI配置，功能上与 Wintun 的标准值一致，不是许可证意义上的实现移植。

## 资源与权限

- 控制设备 ACL 仅 SYSTEM/Administrators；每适配器仅一个文件会话，16个挂起读、16个同步写、64个1280B发送包；过载显式拒绝/计数。
- OS发送 NBL 复制到有限队列后完成；用户读使用 IO_CSQ，取消/清理从唯一队列移除 IRP。一个工作项分发读，不把 NBL 指针交给用户。
- 用户写的 buffered IPv4 数据建立短期 MDL/NBL，以 RESOURCES 方式同步接收指示，返回即回收。Pause/电源下降停止数据、等待当前写、取消读并清队列；Halt 保留打开文件/工作项引用直到退出。
- 用户DLL仅暴露递增 opaque handle，注册表最多8个会话；Stop/Close取消自身 I/O，shared_ptr保留正在使用的对象。C# provider等待 I/O退出再释放 DLL，超时保留资源并报错。
- 只添加本会话创建的 IPv4地址，成功创建才标记所有权；不接管已有地址或删除别人的路由。恢复遗留地址与接口命名仍需真机验收。
- 本研究不承诺防御已拥有内核加载权限的恶意管理员。网络不可信载荷必须经用户态身份/包来源验证后才能写入 TUN。签名、静态分析和内核生命周期检查独立进行。

## 工具链与当前事实

`drivers/Build-Research.ps1` 用 MSVC/WDK，独立于 MinGW与默认产品构建。使用工作区内官方 NuGet WDK x64 10.0.26100.2161，包 SHA256 `66DEF7A3EC39918464CC8955BBC1965FE0C2404755FE5D476E9A6BB953832F9F`，匹配本机 SDK build26100。未运行系统安装器，未装/加载自研驱动。工具包许可证不随产品再分发。

真实研究构建通过 `/kernel /GS /guard:cf /W4 /WX`（仅屏蔽WDK声明的结构填充4324），内核SYS与静态CRT用户DLL链接成功。InfVerif `/w`退出0；最初INF缺最低系统版本装饰的1199失败已保留。C#研究provider构建0警告/0错误；用户DLL 8项负例/ABI验证通过。这些只证明编译、INF和用户态边界，不能证明 NDIS收发/PnP/低内存正确。

**状态：DRV-01 ImplementedUnverified，产品接入Partial；DRV-02 BlockedExternal。** 尚无签名、隔离Windows驱动测试机、Verifier/HVCI/HLK报告或真实provider A/B。必需 Gate 不得由编译、断言数量或模拟器替代。

## 资料

- [NDIS介质：NdisMediumIP](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddndis/ne-ntddndis-_ndis_medium)
- [Raw IP NBL标志与帧类型](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/mb-raw-ip-packet-processing-support)
- [NDIS miniport注册](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ndis/nf-ndis-ndismregisterminiportdriver)
- [WDK NuGet](https://learn.microsoft.com/en-us/windows-hardware/drivers/install-the-wdk-using-nuget)
- [电源OID](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/oid-pnp-set-power)
- [官方Wintun INF的介质和绑定配置](https://git.zx2c4.com/wintun/tree/driver/wintun.inf)
