# M5：来源学习的两台 Windows 原生验证

产品接入提交 `cb93980`，隔离工具最终提交 `4faffe5`。本次两端实际执行自包含 Harness、MeshRunner、MeshLink、Wintun、C++ 和已安装的 WinDivert；没有替换现用 0.3.2 服务。

## 结果

| 来源学习一侧的协议角色 | Thinkbook 连通时间 | Akane 连通时间 | 双端完整回显 | 来源学习 | 双端接收观察窗口 RST |
|---|---:|---:|---|---|---|
| client，Thinkbook 学习 | 16.979 秒 | 17.321 秒 | 各 10/10 | 真实 SYN 的来源端口与公告不同，认证后冻结 | 0 / 0 |
| server，Akane 学习 | 16.062 秒 | 18.349 秒 | 各 10/10 | 同上，角色反转 | 0 / 0 |

连通时间包括启动、网卡、HTTPS 和协商准备，不是八秒原生握手耗时，且没有旧版同条件对照。每个回显携带 1252B UDP 数据，对应完整 1280B 内层 IPv4。没有执行 50Mbps 压测；负载、丢失率和长期性能均为 `NotTested`。

接收头部观察分别记录 41/29、26/47 个报文，观察器 error 均为 0，选定实际 tuple 的 RST 也均为 0。第二轮可见现有 180B HTTP 前导与 48B bare 载荷使用相同 seq/ack；来源学习未改变旧 profile。观测点是接收 Windows 的 NETWORK inbound SNIFF，**不是物理网线、外层 NAT 或全程 RST 抓包**。

两轮都由真实 signed capability/候选、共同 SO、1344B 路径认证及提名建立业务。父捕获 owner、native 进程和 helper Lease 最后关闭；不是只调用一次来源解析函数。

## 网络与夹具边界

原始对等 FakeTCP 报文走两台电脑已有 P2P 虚拟链路，不经本次协调服务器转发。为了独立验证接收范围，受控本地 helper 故意把一端源端口公告为实际端口加七；对端从真实抵达的 SYN 学到正确端口。这是端点差异夹具，不是校园网 NAT 实际改写。

首轮使用直接临时 HTTPS 与远端 helper 的准备路径，双方没有进入候选收集。独立控制探针确认 Akane 对该临时控制端口 TCP 超时，尚未进入 TLS；没有定位是现用链路还是主机过滤导致。该失败不能记为原生打洞失败或成功。

后两轮通过现有 SSH 反向转发**控制 HTTPS**，helper 连接各自在本机形成。业务仍在两端原始路径上收发。此设置避免把控制访问障碍混入来源学习实验，但也意味着：

- 没有证明独立公网冷启动、公网 NAT 新覆盖、任何映射/过滤分类或端口预测。
- helper 为本机流，捕获统计 `HelperReinjected=0`，不能由此补足公网 helper 排除的全部 Gate。
- 新 Wintun 业务功能已验证，不证明外层物理 PMTU 无分片。
- 各角色只执行一轮，不满足受控真机 30 轮、八终端或长期性能发布门槛。

## 证据与清理

本机 `artifacts/`：

- `m5-source-windows-4faffe5-receipt-20261012.json`：四端结果和文件哈希；每角色两台真实 Windows，不能算四台设备。
- `m5-source-windows-{client-role,server-role}-helper-final-20261012-{local,remote}.json`：原始结果、时间线、真实路径身份、源学习与头部观察。
- `m5-source-windows-4faffe5-build-20261012.json`、`m5-source-windows-remote-4faffe5-bundle-20261012.log`：最终提交后构建，双端关键文件一致。
- `m5-source-windows-client-role-20261012-{local,remote}.json`、`m5-source-control-diagnostic-20261012.log`：准备失败和 TCP 控制访问负例，原始记录保留。
- `m5-source-windows-local-cleanup-20261012.json`、`m5-source-windows-remote-cleanup-20261012.log`：无测试进程、监听、临时规则或额外网卡；原服务/原网卡仍在运行。本机原服务 PID 未改变，Akane 注册路径、Running/Auto 未变。

新工具字段 `MeasureLoad=false` 明确关闭压测；`LocalHelper=true`、`ReflectedPortOffset`、`PeerSourcePort` 和 `RequireLearnedSource` 显式描述夹具。默认参数保持既有网络工具行为。第一次复用运行时文件时哈希预检拒绝了不一致组件，尚未发包；随后按最终提交完整重建并同步，保留前后构建收据。

生产代码和配置没有改为此夹具。真实网络、新独立候选、八台 Windows、安装升级与回滚等 Gate 继续待验；来源学习默认关闭。
