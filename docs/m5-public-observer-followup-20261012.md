# M5 公网 TCP 观察补测

从 `fb969dd` 继续，只运行独立观察进程；未替换两端 StreamLink 或生产协调服务，未修改防火墙、网卡、路由、Lucky 或 VMware 配置。

## 结果

| 本机 `artifacts/` 产物 | 实际结果 |
|---|---|
| `m5-observer-public-20261012-001107.json` | Thinkbook 实际物理源地址、真实 WinDivert owner。同一个独占 TCP helper 保持连接；两个高位目标端口各提交三次原生 SYN，均为 `NotObserved`。独立普通 TCP 对照也未增加服务器捕获计数。 |
| `m5-observer-public-20261012-001543.json` | 换为一个已确认普通 TCP 可达的高位 SSH 端口作为观察点，另一个仍用原高位端口。前者取得 **`SynObserved`**，后者仍未观察到。原生 owner 实际收到五个报文，结束后 session 为零，helper 前后查询成功且其公网端点保持一致。 |
| `m5-observer-port-control-run.log` | 尝试使用低于 1024 的观察端口，在已有协议校验阶段被拒绝，没有进入探测；保留为试验准备失败，不能算 NAT 失败。harness 参数已限制为 1024–65535。 |

已观察目标看到的公网源端口，与同一资源的内核 TCP STUN 观察值**不同**。这是该次资源、目的和时间窗下的 TCP 观察差异；不能直接分类为永久 ADM/APDM，也不证明所有将来端口都随机。原始地址留在忽略提交的诊断 JSON 中。

这补足了先前“原生发包没有公网正例”的缺口：至少一个经过授权的原生 SYN 从 Thinkbook 物理出口到达了用户的服务器。同时表明，仅用此前两个无观察结果的端口，不能排除目标端口可达性的影响，更不能归因于 Windows 原生发包必然失效或校园网 QoS。

`captureBefore/After` 是服务端捕获范围内的总数，可能包含同目标端口的其他 SYN；**不能用这个总数计算本次探测丢包率**。`SynObserved` 仍由登记的 ISS、目标和短时窗关联；不是成员身份认证。观察器只读，不绑定目标 TCP 端口、不发送握手回复；已存在的系统服务可能按正常内核行为回复 SYN+ACK/RST。

## 验证边界

- 只有一个服务器公网 IPv4、两个端口，尚无两个独立公网 IP 的完整行为测试。
- `TcpHandshakeVerified` 和 `LegacyPayloadVerified` 都是 `NotTested`。没有完成 SO、HTTP/bare、MeshLink 或 Wintun 的公网认证业务测试。
- 没有外侧线上 RST 抓包证据；owner 的 `KernelSuppressed=0` 不代表线上没有 RST。
- 控制 HTTPS 经临时 SSH 本地转发，SYN 直接发公网目标；没有业务数据经过服务器转发。
- 服务器观察进程有 150 秒内部、160 秒外部期限；补测后确认观察端口已关闭，生产协调服务仍为 `active`。
- Akane 未参与本次公网探测；此前包验证不充当本次 TCP 证据。

## 可复现入口

`scripts/Invoke-TcpObserverPublicFollowup.ps1` 需要显式提供用户管理的 SSH 主机、观察地址、已部署隔离 harness 目录以及 WinDivert DLL；没有提交个人服务器默认地址。`FirstPort/SecondPort` 可指定管理员确认的两个高位端口。程序仅通过现有驱动执行，不能安装驱动；本机还需管理员权限。

先发布 `tests/StreamLink.TcpObserverTests` Linux 自包含版本到新的独立目录；Windows 端构建同项目。脚本在空闲的本机 43983 端口建立仅回环控制转发，验证 pin、运行短探测，finally 停止自己创建的 SSH 子进程。远端进程按强制期限退出。日志、pin 和包含公网端点的结果不放入公开源码包。

本次不改变正式观察协议/捕获代码和数据面，也不启用端口预测或概率探索。后续预测仍需满足计划中的独立观察窗、留出验证、背景干扰和 ≤2 秒新鲜度要求。
