# NIC-01：同一适配接口与官方 provider 实测

扩展既有 IPacketAdapter，未另造一套抽象：provider ID、ABI、IPv4/1280B、取消能力、实验属性、统计和Stop。默认官方 Wintun 用户态桥升级ABI2，增加取消事件及读/写/ring满/截短/等待计数。正式 Router 的读泵观察取消，并在等待I/O结束前Stop；最后仍由已拥有的Adapter清理自身，不操作其他网卡、默认路由或DNS。

网段检测从字符串改为真实IPv4地址前缀及 Windows GetIpForwardTable2：同/24、本机落在该/24或更具体冲突阻断；父网段/VPN /1覆盖保留警告；/0默认路由本身不是冲突。已验证的自有接口可由契约显式排除，默认构造无此证明不能自行认领别人接口。无法枚举路由时明确失败，不靠改网段或删别人路由处理。

本机实际使用同一已固定官方Wintun组件，新建隔离虚拟网卡，真实Windows UDP应用→Wintun→MeshLink→模拟remote，再返回真实应用；ABI2及读计数通过，退出后隔离地址/网卡及精确临时规则已移除。共47项mesh/native检查通过。12项契约/父子/默认/VPN/ownership/取消模型及真实只读路由表通过。此处真实I/O只证明官方provider，没有自研内核驱动/WAN/FakeTCP证据。

证据 `evidence/adapter/` 保留bridge与官方组件hash、环境和原日志。MinGW构建桥接DLL成功，已有官方头pragma/函数指针转换警告保留，不冒充零警告。后续100次停启/并发关闭、UI警告及其他拓扑继续补齐；自研provider没有DRV-02 Gate时不能通过RequireProduction替换官方默认。

## 2026-10-14 后续证据与未通过项

官方适配器读/写/统计/取消和释放已加并发句柄保护，取消不提前释放仍使用的句柄；源码ABI仍为2。最新1073项Mesh回归包含真实Windows UDP应用→Wintun→MeshLink→原UDP应用返回，单次清理通过。100次并发停启未完成：即时接口消失断言Fail，诊断等待再次超时。所有Fail保留在 `evidence/adapter/rc1-final/`；尝试的PnP确认等待及额外identity接口已撤回，不靠扩大时间门槛取得通过。单次成功不能替代该生命周期Gate，自研内核验证仍Blocked。
