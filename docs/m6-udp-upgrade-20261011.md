# M6：UDP 降级后后台恢复 FakeTCP

从 `f809e05` 继续。现有实验模式原来在 UDP 连通后停止收集候选，FakeTCP 条件恢复也不会自动提升。本次将后台升级接入实际 `MeshRunner → MeshTraversalManager → MeshRouter`，没有修改原生 HTTP、SEQ、加密或业务数据报语义，没有更新现用服务或网络配置。

## 产品行为与资源边界

- 仍需显式开启实验 `tcp-udp` 和 UDP 降级；默认兼容入口与 UDP 默认关闭均不变。双方必须公告 FakeTCP SO 能力和 `BackgroundUpgrade=1`。旧公告缺少新增字段视为 0，避免向不支持保留 Active 的旧调度器反复提交升级。
- 同一健康 UDP 路径连续驻留至少 30 秒后，较小成员编号端可以发起升级。失败后至少冷却 60 秒；原有失败退避更长时仍受其约束。这两个值是后台恢复的工程初值，不能解释为负载质量证明。
- 未连通设备的可执行前台工作先获得机会，后台升级继续使用全机两轻量、一原生及共同请求预算。没有新增每 peer 轮询或预算旁路。
- Router 只允许健康受管 UDP 为一个 FakeTCP 候选预留位置；健康 FakeTCP、兼容路径、尚有 Candidate 或退役引用时均拒绝这项替换。
- 旧 UDP 的 Selected Actor 在新候选期间仍被保留。候选失败只取消候选，清理完成后恢复旧 Actor；旧获胜 socket 不重建。新路径共同提名成功并且旧路径实际退役后，才清理旧准备引用。
- 关闭软件时遍历 Candidate 与 Previous 的所有者链；延迟清理任务也被等待。成员撤销仍由 Router 先撤销实际收发能力。
- 新 FakeTCP 使用原来的认证、实际包长验证、八秒 SO 期限和共同提名。这里没有实现 AutoQuality，也没有声称空载连通等于已满足 50 Mbps。

## 本次证据

`artifacts/m6-upgrade-capability-20261011.json`：最终版本，正式两 Runner、真实 HTTPS 协调、真实回环 UDP socket、原生 C++ 协议测试后端；内层使用内存 IP adapter。候选收集和故障由夹具控制，无 WinDivert/Wintun、物理 NAT 或公网覆盖证明。

15 项检查通过，具体过程：

1. 首个 FakeTCP 收集故障后选择 UDP，约 36.513 秒报告降级连通。以旧能力公告继续运行超过 35 秒，未发生额外原生候选分配；随后经实际签名公告启用升级能力。
2. UDP 保持业务时，第一次后台升级在两端已准备原生资源之后注入激活失败；约 80.783 秒观察到两端失败资源已回收，UDP socket 身份与引用持续有效。
3. 冷却结束后恢复原生后端，约 143.528 秒双方完成 FakeTCP 提名。旧 UDP 路径和准备引用随后全部释放。
4. 成功切换后继续运行超过 30 秒，未额外收集候选。双向各发送 1174 个 1280 字节合成内层包，最终每个序号恰好交付一次，状态采样未观察到连接中断。
5. Runner 退出后全部测试 socket、原生资源和 IP adapter 均释放。

上述时间从整个用例启动计时，包含故意失败、30 秒退避/驻留和 60 秒冷却，不能当作正常连接或故障恢复时间。初次降级之前约 30 秒的普通方法退避也暴露了现有前台机会窗调度的后续优化点。本测试是约 10 包/秒的小负载生命周期验证，不替代 50 Mbps、时限送达或长时间串流验收；“最终全部收到”不等于零迟到。

能力字段加入前的中间版本记录保留在 `m6-upgrade-runner-20261011.json`（13 项通过、双向各 1068 包），不代替最终版本的能力协商验证。

`artifacts/m6-upgrade-managed-20261011.json`：52 项 Router 检查通过，新增健康 FakeTCP 不接受后台替换预留；同时复跑提名失败、旧/新引用、去重、撤销和双向健康。这里的 FakeTCP 是路径策略标签，不是原生 I/O。

新增能力字段后的正式 Runner 与收集器回归另存 `m6-upgrade-baseline-final-20261011.json`：54 项检查通过，覆盖旧能力 JSON 缺省、未知升级版本拒绝、签名准入、全机并发预算、三 Runner 共享源、两协议业务与退出。应用 Release 构建零警告、零错误。测试工具新增长用例分组；默认不加选项时运行两组，以下命令只运行升级：

```powershell
dotnet run --project tests/StreamLink.MeshRunnerTraversalTests -c Release -- --native out/native/udp2raw-protocol-test.exe --rounds 1 --output artifacts/m6-upgrade-runner.json --upgrade-only
```

`--baseline-only` 仅运行原有调度/三 Runner/两协议回归。不要在同一输出目录里同时构建并运行该 Windows exe；会遇到 apphost 文件占用重试。本次基线构建曾等待升级进程释放文件后继续，未终止升级测试或修改产品逻辑规避。

## 未完成与回滚

AutoQuality、方向性负载证据、出口 pacing、真实严格 NAT、八台物理 Windows、长时间负载和正式安装包 Gate 仍未完成。前轮两 Windows 的反向负载失败仍然有效，本轮没有重新测公网或把该失败改记为通过。

现用部署未改变。开发版本可退回 `f809e05` 恢复为仅策略保护、不进行 UDP 后台升级；设备配置字段没有变化，回退无需转换配置。无需变更 Lucky、路由器、驱动、VMware 或物理网卡。
