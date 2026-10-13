# ADR：独立有界 WFP 研究（DRV-03）

WFP 捕获与 L3 虚拟网卡是不同职责。`drivers/StreamLink.CapturePoC/driver.c` 是独立研究驱动，默认产品继续 WinDivert。它没有修改 HTTP、SEQ、密码、TUN或业务承载。

本轮样机限于 IPv4 TCP TRANSPORT 层、最多32个准确tuple、SYSTEM/管理员控制文件、独占控制者与双向观察计数。同tuple不同代次拒绝冲突；控制文件关闭/崩溃清理授权表及本驱动BFE过滤器，动态engine在卸载时关闭。未授权tuple不记录或操作业务。没有全局 RST抑制、没有包阻断、没有 kernel业务队列。

样机调用 `FwpsQueryPacketInjectionState0`区分自己/之前自己及其他来源注入，避免未来捕获循环的错误假设。**当前尚未实现注入请求与异步完成的完整资源接口，也未产生真实自注入数据**，故注入循环验证记 NotRun，不把代码分支存在算成通过。两个协议过滤器会进入TCP inspection回调，再按授权tuple筛选；未来需评估精确逐tuple过滤及成本。

MSVC/WDK研究编译与链接已通过，SYS未签名，未安装/加载。缺隔离驱动真机与签名；源级样机记 Partial，真实BFE关闭/服务失联/自注入观察均未实测。未有收益证据前不替换 WinDivert，不把此样机描述为可用默认捕获后端。

后续隔离 Gate：授权/未授权正负例、相同四元组冲突、控制者退出、BFE重启、暂停恢复、跨驱动注入、自己的重复注入、坏载荷、取消与卸载并发。正式数据接口需继续遵守 EndpointOwner唯一归属、helper tuple排除、资源引用及捕获准备后才能发送。
