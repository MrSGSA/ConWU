# 高级协调与生日碰撞实验

2026-11-17，开发版本仍为 1.5.0。默认模式、三机安装、主机审批和业务承载保持原流程。本轮生日碰撞只进入显式启用的独立实验，没有接入用户的正式网络。

## 双端主动探测

高级协调模式已包含双方主动探测。首次配对中，主机按协调轮次调用 `Engine::punch_unpaired`，从机等待同一轮次后通过已观察的源端点主动建连；已配对成员也各自请求和执行同一轮次的建连。协调服务器交换候选并调度，不承担业务中继。TCP／HTTPS 使用系统 TCP，其余四种承载使用各自的 TCP 外层实现，不能将它们概括为已支持通用 UDP 打洞。

后续实验仍须抓包核实双方实际发出 SYN、同源端点复用及 SYN-ACK／RST／重传。服务端发出轮次、观察到 STUN 端点和真正双向连通分别记录。主机和从机是授权角色，不能据此固定外层连接的发起方。已配对复连与首次 SAS 审批分别验收。

## GitHub 源码核对

本轮下载固定提交的公开源码供阅读，没有执行上游代码，也未将其代码搬入 MIT 核心。

| 来源 | 核对内容 | 对当前实验的意义 |
| --- | --- | --- |
| [danderson/nat-birthday-paradox](https://github.com/danderson/nat-birthday-paradox/tree/862c8cc51e24a3ac9a7da61bc01daab9f719c84e)（GPL-3.0） | README 与 `paradox.py` 区分一端稳定、两端目标相关映射的端口组合空间 | 一端稳定时可匹配两个端口集合；双端随机时须匹配镜像的端口对，难度明显增加 |
| [EasyTier TCP](https://github.com/EasyTier/EasyTier/blob/fbf0776cde10f437d6972206d69ca050fe27abe3/easytier-core/src/connectivity/hole_punch/tcp.rs)（LGPL-3.0） | 同源 TCP 套接字、主动探测、协议角色与 NAT 策略；该版本的发起路径跳过本端对称／未知 TCP NAT | 不能把其 UDP socket array 的收益直接套给 TCP，更不能据此断言双 NAT4 TCP 已解决 |
| [EasyTier UDP socket array](https://github.com/EasyTier/EasyTier/blob/fbf0776cde10f437d6972206d69ca050fe27abe3/easytier-core/src/connectivity/hole_punch/udp/socket_array.rs) | 有界套接字数组、探测事务标记、命中后的套接字交接与资源退出 | 多映射和实际命中交接值得研究，TCP 生命周期与状态跟踪仍需单独实现 |
| [frp NAT 策略](https://github.com/fatedier/frp/blob/a2c975efb5e55102068065d61cfc17ffe34e939d/pkg/nathole/analysis.go)（Apache-2.0） | 按映射规律组合随机目标端口、多监听端口、发送时机、有限端口范围及退避 | 应按实际 NAT 行为选择有界策略，不能只按“NAT4”标签给出统一成功率 |

其他已检索资料包括 kupson/udp-hole-punching 与 uk0/stun_max；尚未将其自报成功率作为结论。固定提交、URL、文件 SHA-256 与许可证证据保存在本地 `out/birthday-punch-20261117/`。

## 独立 TCP 原型

入口为 `rust/birthday-nat-lab.sh` 与 `rust/birthday-nat-lab.py`。必须显式传入 `--enabled`；需要 Linux root 及 mount/network namespace 权限。所有句柄、日志和结果位于当前仓库 `out/lab/birthday-*`，命名空间与子进程在 `finally` 中回收，不修改生产路由器、服务或身份。

实验建立两个独立 SNAT 路由器和一个无外网出口的桥接观察节点，禁止未经 conntrack 匹配的入站，未设置 DNAT。A 从固定本地端点建立并保留观察连接，B 从多个套接字向 A 观察端点发起 SYN；A 从同一源端点向 B 的随机端口集合发起 SYN。两端都是主动 TCP 连接，不依赖被动公网监听入口。命中后交换带本轮密钥与随机会话标记的 HMAC 报文和接收回执，检验真实双向数据。该认证仅是夹具验证，不签发 ConWU 成员身份，也不替代 SAS／MeshLink。

套接字与目标探测各最多 128 个，每组最多 8 轮、每端每轮最多 8 秒。默认各 64、3 秒、3 轮。每个 WAN 使用只读 AF_PACKET 捕获报文头，记录 SYN 的源／目标端口、序列号、ACK 与时刻，不保存业务载荷；另外保存实际 nft 规则和进程清理结果。

首轮使用缩小的 1024 端口空间，验证机制和状态跟踪，不代表公网端口分布。最终证据 `out/lab/birthday-601f9c78/`：

| 条件 | 预算 | 双向认证成功 |
| --- | --- | --- |
| 一端稳定，另一端随机；单端口基线 | 1 个映射 × 1 个随机目标 | 0／1 |
| 一端稳定，另一端随机 | 64 个映射 × 64 个随机目标 | 3／3 |
| 两端按目标随机映射，严格回包匹配 | 每端 64 次主动探测 | 0／3 |

每轮都观察到双方实际 SYN；双随机组核实 A 的实际 WAN 源端口发生变化，而非只改变候选标签。所有本轮子进程与命名空间清理检查通过。少量样本只证明在所述夹具中出现过／未出现过命中，不能用于估计公网成功率。前期夹具错误与被修正的中间样本保留在本地，不混入上表。

## 理论与下一步

若一端的公网源端点在所有目标间保持稳定，另一端建立 m 个独立映射，稳定端从同一端点向 n 个目标端口探测，则在均匀、独立及映射存活等假设下可用 `1-exp(-mn/N)` 近似端口集合碰撞概率。两端都按目标随机分配端口且要求精确回包时，需要匹配端口对；在相应简化模型中空间约为 `N²`。TCP NAT 还可能拒绝交叉 SYN、提前回 RST 或更改映射，因此碰撞概率仍不等于完整 TCP／SAS／业务成功率。

后续在日用会话空闲时验证完整端口空间、目标相关但有规律的分配、TCP simultaneous open、RST 与超时策略、两端映射寿命及取消清理。优先比较有限预测与多映射的实际收益，再决定是否给高级 TCP／HTTPS 模式增加默认关闭的产品实验入口。Mimic 等单源原始承载须另做端口所有权与握手适配，不能直接套用套接字数组。

用户使用 UU 时不在同机并行进行此类 NAT 实验、重负载构建或 Wintun 重建。2026-11-17 已出现 999ms 卡顿，停止开发测试后用户确认明显缓解；后续验证需遵守 `AGENTS.md` 的日用会话约束。
