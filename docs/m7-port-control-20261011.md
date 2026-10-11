# M7：PCP / NAT-PMP Provider 与 TCP 入口接入

本文记录 `63d09a2` 的阶段状态。后续 UDP_DIRECT 接线与共享控制资源见 [UDP 网关接线记录](m7-udp-gateway-20261011.md)；本文原始验证产物保持不变。

10 月 12 日补充：[单播通知与复核](m7-gateway-notifications-20261012.md) 已接入共享控制 socket 的唯一接收者；PCP MAP/ANNOUNCE、NAT-PMP 单播提示不再只等待下一次续租。组播仍待完成，以下关于异步通知的描述是本页早期状态。

从 `63f04d5` 继续。本次完成 IPv4 网关 Provider、TCP 后备入口和生命周期回归，**M7 仍为部分完成**。尚无真实 PCP/NAT-PMP 路由器到双 Windows 业务的正例；UDP_DIRECT 接线和原生 IPv6 也未完成。现用服务、Lucky、驱动和网卡配置未改动。

## 产品行为

- `DeviceProfile.PortControlMapping` 默认 `false`。设置 → STUN 与端口设置新增“TCP PCP / NAT-PMP 后备映射（实验，需网关支持）”。后台通过 `PortControlVersion=1` 声明支持；旧后台缺字段时禁用该项。关闭开关后仍使用原 TCP STUN + UPnP P→Q 流程。
- 显式开启后，原 UPnP 路线优先；发现/申请未成功才进入新 Provider。它在 Runner 已有的独立 Probe 任务中运行，其他成员入口及受管打洞不等待网关重传。当前仍须先成功建立 TCP helper，尚未实现“STUN 全部不可用但网关可用”的独立收集。
- PCP 为监听 Q 申请 TCP 映射，以 P 为建议外部端口。发布的是网关**实际返回**的公网 IPv4 和端口。不会把内层私网/CGN 地址替换成 helper 的公网 IP，也不会拼接不同映射的端口。仅有内层成功时拒绝该候选；旧 UPnP 的已验证映射链保持原处理。
- TCP helper 观察、网关租约和真实认证路径分别处理。helper 超时后清除观察并后台重试，仍有效的网关入口继续续租。网关端口变化更新公告；候选失效后停止公告。只有原有 MeshLink 双向验证能决定 Active。
- MeshRunner 在 FakeTCP 映射维护失败时保留现有监听进程，避免因元数据失效直接终止其中的 peer 会话。新的本地源地址与监听地址不同时重建；原生退出、用户停止仍回收。旧 raw UDP 依赖 helper 的共享绑定，继续原来的重建路径。保留进程并不保证失效的 NAT 状态仍可通信。

## 资源与协议范围

新增 `PortControlProtocol`、`PortControlRoute`、`PortControlLease`。Provider 返回实际端点、协议、租期、epoch、网关、接口/路由标识、所有权、状态和清理结果；PCP 96 位随机 nonce 保留在本地内存，不发送至协调服务或普通日志。

只发现源地址所属的以太网/Wi-Fi 默认网关，要求 IPv4 同子网，目标固定为 5351；排除 StreamLink/Wintun/EasyTier 网卡。不接受用户任意公网控制地址，不扫描网关。当前未实现 DHCP PCP Server Option、跨层显式 PCP 配置、NAT64、IPv6 PCP。

每个租约独占一个控制 UDP socket，使用 `TraversalResources.Shared` 的八 socket 总额度及维护包桶。它不替代 native 的 Q 或 UDP 业务 socket。按网关串行交换请求；本进程同 local/protocol/internal-port 不允许两个租约所有者。网关串行排队也消耗原租约剩余时间，不能推迟过期。源接口/默认网关每秒复核；网络变化清理可用性退避缓存。该路由标识不是网关硬件身份，重启主要通过 epoch 观察。

PCP 先请求 180 秒，按实际返回值维护；过短（小于 8 秒）的租约不发布。请求采用 3 秒起始抖动与指数退避，本次选择器最多四次发送；续租以授予期限的随机比例安排。响应须来自 connected socket 的准确网关，并匹配 nonce、协议、内部端口；校验长度/选项结构，忽略未知响应选项。设计依据为 [RFC 6887](https://www.rfc-editor.org/rfc/rfc6887.html) 和 [RFC 7488](https://www.rfc-editor.org/rfc/rfc7488.html)。

仅收到 NAT-PMP 的明确不支持版本响应才降级；超时、错误、畸形报文均不触发降级。随后串行查询外部地址、申请映射；保留实际端口、租期和 epoch，半租期续租。协议重传从 250ms 指数增长，最多九次发送。普通失败约 15 分钟后允许再探测，匹配错误使用服务器要求的退避期；用户取消不记为永久不支持。依据 [RFC 6886](https://www.rfc-editor.org/rfc/rfc6886.html)。

PCP 清理只发送本租约的精确 nonce/协议/内部端口，无通配删除。取消但响应不明时也只尝试该 nonce；明确错误或路由改变时不删除。NAT-PMP 缺少同等的 nonce 所有权证明，因此**从不发送删除请求**，停用后等待实际租期到期。日志区分 `DeleteConfirmed`、`DeleteNotConfirmed`、`NaturalExpiry` 和跳过删除；不能把“本地资源关闭”当作“网关已删除”。

当前实现按请求/续租响应检查 epoch 和端口变化，未实现 PCP ANNOUNCE、空闲期间主动消费 Mapping Update、NAT-PMP multicast 重启通知。网关变化尚未被收到/确认之前，仍存在候选短时陈旧窗口；实际路径检查不能省略。该限制也是保持实验开关的原因之一。

## 本轮验证

运行 Windows 普通用户态回环套件，不加载 WinDivert/Wintun、不向真实路由器发送控制请求。夹具返回的 `1.1.1.1` 仅是编码字段，测试没有向该地址发包。

| 产物 | 结果与范围 |
|---|---|
| `artifacts/m7-port-control-20261011.json` / `m7-mapping-test-20261011.log` | 276 个检查，其中新增 Provider 266 项、原映射测试 10 项。30 轮只是 TCP/UDP 编码与 nonce 随机输入，不是 30 次 NAT 穿透。9 组真实 OS 回环网关场景含来源/nonce/操作错误、超长包、明确降级、错误退避、取消、epoch 变化、内层 CGN 拒绝、续租过期/排队和正式 TcpMapping + TCP helper。 |
| `artifacts/m7-mesh-connection-test-20261011.log` | 46 项。正式 MeshRunner + 内存网卡/替身传输验证失效公告撤回、保留监听所有者、独立回收和其他已认证路径继续收发；不证明 WinDivert 接入的入站会话实际续传。 |
| `artifacts/m7-connection-test-20261011.log` | 19 项旧版双机 Runner 回归，内存会话与协调。 |
| `artifacts/m7-runner-baseline-20261011.json` | 55 项正式 Runner 基线通过，含三实例全互联、TCP/UDP 候选和完整内层包。原生协议测试后端，不加载驱动，不代表三台真机或公网 NAT。 |
| `artifacts/m7-settings-20261011.png` | 本机 DPI 下的连接设置预览，实验开关默认未选中；无控件重叠。 |

应用、服务及上述测试项目 Release 构建零警告、零错误。完整产物路径与 SHA-256 见 `artifacts/m7-port-control-manifest-20261011.json`。

## 后续 Gate 与回滚

M7 剩余工作包括 UDP_DIRECT 同 socket 租约接线、网关异步更新通知、独立于 STUN 的映射收集、真实默认网关和外层 NAT 到 native 的认证业务验证，以及完整原生 IPv6 链。现有 UDP 编解码支持不等于 UDP_DIRECT 已接线。未更改严格 NAT 成功率、八设备或公网质量声明。

关闭实验开关并保存可回到原入口流程；保存会按现有产品行为重新连接。PCP 尽力精确清理、NAT-PMP 按返回租期到期。代码回退可还原本次提交；新 profile 字段为可选布尔值，旧配置自然取 false，旧服务忽略未知字段。本次未升级生产服务、修改安装目录或发布安装包，因此无需撤销设备配置。整个 M0—M9 的正式安装包、八真机和长期验证仍待后续交付。
