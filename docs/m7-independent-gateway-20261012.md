# M7：显式网关候选不再依赖 STUN 成功

基线 `f0fed51`。原 TCP 映射流程必须先完成 TCP STUN；UDP 网关轮次也先解析 STUN 目标来选择源地址。STUN 全部不可用时，即使本地网关能返回独立可达的入口，也没有收集机会。本次把入口来源分开，保留正常情况下已经有效的 STUN + UPnP 路径。

## 产品接线

`PortControlRoute.LocalSources()` 从实际启用的物理以太网/Wi-Fi 接口中收集最多四个 IPv4 源地址，并要求存在当前、同链路的默认网关。排除已知虚拟隧道接口，不解析或访问 STUN 域名。之后的 Provider 仍复核实际网关/接口代次，候选仍须经真实对端认证；枚举不是可达性证明。

TCP：

- `MeshRuntimeServices` 和旧双机 `RunnerServices` 改由 `GatewayMapping.CreateTcp` 组织入口收集。
- 首先运行原 TCP STUN + UPnP 流程；成功时直接保留原映射。只有启用了原有 `PortControlMapping` 实验选项、旧流程失败并已释放自己的 helper/规则后，才运行独立 PCP/NAT-PMP 收集。
- 两个映射协议不会并发操作同一个监听端口 Q。新入口申请实际 Q 的 TCP 映射，建议外部端口为 0，由网关返回实际分配值；不拼接其他 STUN 的外层 IP/端口，也不占有伪造的 helper P。
- `GatewayMapping` 实现既有 `IMapping`，持有明确的 TCP/本地地址租约，提供续租、通知、端点变化、失效和回收。原生监听仍通过现有传输层持有 Q，新类不二次绑定它。
- 外部地址若属于内层/CGN 范围则拒绝发布并清理自己的 PCP grant。NAT-PMP 保持自然到期、不主动删除的规则。
- 用户取消不会触发新 Provider；旧步骤自己的超时可回退。旧流程耗时仍存在，本次没有宣称 TCP 首次入口必然在几秒内产生。

UDP：

- 网关轮次直接从本地出口创建受管、唯一持有的数据 socket，再为该 socket 申请映射。完全不要求 STUN 解析或响应成功。
- 普通 STUN 轮次若没有产生候选，且已开启网关选项，也可在**同一轮剩余准备时间**内尝试网关。开启此选项时普通观察上限为 4.5 秒；外层准备期限仍为 12 秒，不为后备重置期限。IPv6 等先前工作消耗的时间同样计入实际剩余时间。
- 若 STUN 产生了候选但真实对等检查失败，保留原来的下一轮网关尝试，不把连接失败等同于 STUN 服务故障。
- 身份、来源、网关 grant、候选有效期、Prepared 与获胜 socket 继续使用原契约；网关轮次不把 STUN socket 的观察移交给另一个 socket。

默认值没有变化：显式映射仍关闭，UDP 仍需既有 `tcp-udp`、降级许可和双方能力。健康 FakeTCP 不被本次候选抢占。假 TCP profile、业务数据报语义以及禁止服务器/成员中继不变。

## 验证

产物在 `artifacts/`，提交及文件哈希见 `m7-independent-gateway-receipt-20261012.json`。

| 产物 | 结果 |
|---|---|
| `m7-independent-mapping-final-20261012.json` | Provider **346** + 原 UPnP 10 = **356 检查**，约 81.14 秒。包括无 STUN 服务的独立 TCP、P 端口未被占用、通知更新、跨出口失败清理、CGN 拒绝、内部超时与用户取消的区别 |
| `m7-independent-runner-second-20261012.json` | **44 检查**。含 DNS 全失败/空列表的收集器测试、现有网关回退链路，以及全部配置 STUN DNS 失败时两个正式 Runner 的完整通信 |
| `m7-independent-connections-20261012.log` | **46 检查**。受控 TCP/组网入口、元数据失效保留监听、故障恢复、签名撤销和退出回归 |
| `m7-independent-app-build-20261012.log` | 核心、服务、应用 Release 构建无警告/错误 |

正式 Runner 对照：已有 STUN 候选但对等检查失败的场景约 **16.507 秒**连接；配置的 STUN DNS 全失败、独立网关成功场景约 **8.798 秒**连接。它们是不同条件的单次本地夹具结果，不能作为公网性能提升比例。后一个场景双方仅各收集一次就完成连接；没有发 STUN 数据报，也没有使用旧传输或业务中继。

两场景均使用真实回环 HTTPS/UDP/PCP/NAT-PMP、正式 Runner/MeshLink 与内存 IP 适配器，双向发送完整 1280B 内层包，并继续检查映射元数据失效后的 Active 寿命与最终清理。DNS 失败和可用源接口由明确的测试接缝注入；**没有真实公网 DNS 故障、路由器转发、WinDivert 或 Wintun 验收**。

TCP 用例通过正式 `TcpMapping.Create` 的无 STUN 列表失败进入独立分支，并实际收发回环 PCP 数据报。它证明资源与 Provider 生命周期，不包含本次独立入口上的原生 FakeTCP 公网业务。正式服务接线通过编译和接口回归，真实双 Windows Gate 仍待执行。

首次 Runner 测试用了空 STUN 列表，在 `DeviceProfile.Validate` 处被拒绝，记录保留在 `m7-independent-runner-20261012.log`，没有通过的 JSON。产品当前仍要求配置列表非空；随后改为有效格式的列表配合确定的 DNS 失败，保留配置校验。底层收集器的空列表测试不代表界面已经允许删除最后一个 STUN 条目。

## 限制与回退

当前只在网关本身能返回合格外部地址时形成独立候选；内层映射不能自动打通外层 CGN。TCP 原生 SO、预测所需的同源观察资源也没有因此被省略。多出口枚举最多四个，不承诺选择了最佳出口；真实路由/网关兼容性必须另外验证。

本次没有修改现用服务、Lucky、驱动、防火墙或网卡。安装包尚未刷新，仍不能当作本次代码的分发物。关闭原 PCP/NAT-PMP 实验选项并重启该网络会保留原路径；代码回退基线为 `f0fed51`。
