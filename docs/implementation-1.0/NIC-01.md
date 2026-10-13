# NIC-01：同一适配接口与官方 provider 实测

扩展既有 IPacketAdapter，未另造一套抽象：provider ID、ABI、IPv4/1280B、取消能力、实验属性、统计和Stop。默认官方 Wintun 用户态桥升级ABI2，增加取消事件及读/写/ring满/截短/等待计数。正式 Router 的读泵观察取消，并在等待I/O结束前Stop；最后仍由已拥有的Adapter清理自身，不操作其他网卡、默认路由或DNS。

网段检测从字符串改为真实IPv4地址前缀及 Windows GetIpForwardTable2：同/24、本机落在该/24或更具体冲突阻断；父网段/VPN /1覆盖保留警告；/0默认路由本身不是冲突。已验证的自有接口可由契约显式排除，默认构造无此证明不能自行认领别人接口。无法枚举路由时明确失败，不靠改网段或删别人路由处理。

本机实际使用同一已固定官方Wintun组件，新建隔离虚拟网卡，真实Windows UDP应用→Wintun→MeshLink→模拟remote，再返回真实应用；ABI2及读计数通过，退出后隔离地址/网卡及精确临时规则已移除。共47项mesh/native检查通过。12项契约/父子/默认/VPN/ownership/取消模型及真实只读路由表通过。此处真实I/O只证明官方provider，没有自研内核驱动/WAN/FakeTCP证据。

证据 `evidence/adapter/` 保留bridge与官方组件hash、环境和原日志。MinGW构建桥接DLL成功，已有官方头pragma/函数指针转换警告保留，不冒充零警告。后续100次停启/并发关闭、UI警告及其他拓扑继续补齐；自研provider没有DRV-02 Gate时不能通过RequireProduction替换官方默认。
