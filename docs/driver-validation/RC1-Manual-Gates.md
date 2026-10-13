# 自研驱动人工验收与阻塞条件

当前仅研究构建。默认安装包不得包含自动加载/替换这些驱动的步骤。

1. 准备独立Windows11 x64测试机/虚拟机、可用控制台与完整恢复镜像，确保测试不依赖该驱动承担唯一远程链路。记录SDK/WDK、OS、HVCI、SecureBoot及真实源码commit。
2. 由拥有合规签名凭据/Hardware Dev Center授权的发布者产生签名CAT/SYS。关联源码树SHA、编译日志、SYS/DLL/INF/CAT哈希及证书链。当前没有这些凭据，标记BlockedExternal；不能通过关闭安全功能完成发布Gate。
3. 在隔离机核对InfVerif、APIValidator/静态分析、签名与PE架构；以官方设备创建流程安装 ROOT\\StreamLinkTun（仅添加INF不会保证创建root设备）。记录接口index/LUID。安装与移除只针对该硬件ID及其具体实例。
4. 正式接口契约：独占打开、ABI/Mtu、错误接口/版本负例；先建立准确1280B IPv4双向收发，再接研究provider与MeshRouter。不能拿用户DLL的无驱动负例当这一步通过。
5. 做100次开关/读取消/进程崩溃/驱动重启；16挂起读与超额负例；64包过载；低内存；Pause/Restart/D0-D3/SurpriseRemove/Halt；取消IRP与队列分发竞态。记录内核残留、句柄、用户DLL在途关闭及地址清理。
6. 在有控制台/恢复镜像的隔离机跑针对性Driver Verifier、HVCI和适用HLK；保留蓝屏dump、失败与修复记录。没有真实报告仍为BlockedExternal，不能在当前生产机启用全局Verifier。
7. 同一Wintun/研究TUN、同二进制/拓扑/负载进行50Mbps A/B、时延与60分钟稳定性；验证现有HTTP/SEQ和不经中继。新provider若退化、生命周期不明或未签名，继续默认官方Wintun。
8. WFP样机另测授权tuple、控制者丢失与BFE清理。实际注入接口未实现，先记Partial；不能宣称已验证捕获、RST或注入循环。

本轮外部状态：无独立驱动测试机、无签名/HLK授权；驱动没有加载。以上步骤不得在材料中改写为Passed。
