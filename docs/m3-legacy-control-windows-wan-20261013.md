# 兼容控制准入：两台 Windows 的公网数据验证

准确测试来源：`c999d02cdbe8844691ddc684fcead61ea67dfee9`。2026-10-13。两端仍安装并运行0.3.2；本次使用各自独立的自包含MeshHarness、新网络身份、新Wintun网段及单独端口。没有安装候选或修改Lucky。

## 拓扑和结果

Thinkbook校园网与Akane移动宽带。业务由Thinkbook物理网卡直接访问Akane的TCP STUN+UPnP公网候选；Akane创建临时、带本轮所有者标识的P→Q映射。真实WinDivert/native、MeshLink、MeshRunner和Wintun均参与，未用内存IP适配器。

临时HTTPS协调运行本机独立进程，绑定既有虚拟接口，双方按本轮证书SHA-256指纹验证。**控制依赖已有组网，业务访问新公网候选。**因此这是公网业务功能验证，不是无旧网络的冷启动验证；也不是共享P端点或原生SO的PoC。

| 观测 | Thinkbook | Akane |
|---|---:|---:|
| 本进程首次报告连接 | 20,921ms | 37,891ms |
| 本机虚拟网卡就绪 | 约3,947ms | 约558ms |
| 发起完整1280B IPv4包（1252B ICMP payload，DF） | 10/10返回 | 10/10返回 |
| 该10包RTT范围/均值 | 18–35ms / 24ms | 19–55ms / 27ms |
| 父端原生控制请求/许可 | 240/240 | 227/227 |
| 父端预算/窗口拒绝、过期、未完成等待 | 均0 | 均0 |
| 最后原生快照业务包/外层IP字节 | 20 / 28,920 | 20 / 28,920 |
| 原生注入失败/捕获队列丢弃/控制管道失败 | 均0 | 均0 |

Akane先启动约17秒，两个进程的计时不能直接相减得到握手耗时。Thinkbook的20.921秒超过计划15秒冷启动目标，**速度目标未通过**；本轮不是严格同步冷启动。50Mbps/20秒、60分钟、物理线上RST、所需NAT组合和八设备也没有在此轮验证。

快照报告的原生注入计数不等同于网卡交付；双端ICMP回包独立证明了这些完整业务包的往返。最后状态是停止前最近一次快照，不作为最终全量计数。helper自动ACK等不可调度开销继续Unknown。实际客户端源为物理接口，目标为新公网候选，确认业务没有经测试协调器或原有虚拟网络代转。

## 产物与复现

本机 `out/m3-win-control-second-20261013/`：`thinkbook-result.json`、`akane-result.json`、双端日志和`*-full-mtu-ping.txt`。Akane独立目录：`E:\Codex_Workspace\Streamlink\isolated-c999d02-second-20261013`。

- Thinkbook结果SHA-256：`4B8774B7D45F8A6BC7E29F6863203570216A485B13F60F346120ACF77750AC11`。
- Akane结果SHA-256：`8F54C7A675B097EE7A1B2CF70A7B13CBE01AD78080AB8EDCA316F56C63F03FEB`。

以 `dotnet publish tests/StreamLink.MeshHarness -c Release -r win-x64 --self-contained true` 构建，配套生产native及tun DLL。准备独立证书指纹、协调目录和双端私有profile后，各执行 `StreamLink.MeshHarness.exe run <本轮profile> <有界运行秒数> <结果JSON>`。网络可用后双向执行 `ping -n 10 -f -l 1252 <对端虚拟IP>`。协调和业务路径分别写入环境清单，私有profile、证书私钥及授权材料不发布。

## 首轮准备负例与清理

首轮 `out/m3-win-control-20261013/` 保留：Thinkbook读取404，Akane连接临时HTTPS超时，未开始业务测试。核查发现本机已有用户生成的.NET Host入站Block规则；同端口Allow不能覆盖它。没有删除该阻止规则或关闭防护，第二轮改用软件自身独立协调EXE，并添加只允许指定对端/本地地址/端口/程序的本轮规则。实际对端HTTPS健康访问随后成功。

两轮均按独立期限退出；Akane记录所属UPnP租约删除，临时协调进程与规则已移除。两端生产服务保持Running/Auto，路径仍为0.3.2；本机生产native PID未变。新虚拟网段和本轮子进程清理另行核对，私有测试材料不进入发布附件。

该证据提升“兼容原生控制准入已接真实Windows公网数据”的状态，不提升整个M1/M2/M3/M9 Gate。共享P所有权、SO、严格NAT覆盖、八真机及安装回退仍需分别验收。
