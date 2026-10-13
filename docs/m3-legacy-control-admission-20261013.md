# 兼容原生控制包在注入前共用预算

日期：2026-10-13。承接 `f563e6e` 的注入观测与网络唤醒实现；不改变已发布 0.5.5 安装包或现用服务。

## 实现与正式接入

`MeshTransport` 在启动子进程之前建立受限 Windows named pipe。双方校验实际父子 PID 和每次启动的随机授权；能力查询要求配套 native 支持 `legacyControl:1`，不匹配的组件明确拒绝启动。授权不写入日志。子进程在授权、捕获和接收循环就绪后才发送。

`native_legacy_control` 将 SYN、HTTP、协议确认和维护报文放入最多八包的本地队列；父端按真实外层 IP 字节、种类和 tuple，通过现有 `TraversalResources.Shared` 领取发送许可。全机 60pps、burst 8、64KiB/s 和维护子额度共用，兼容 tuple 的八秒/120包窗口保留24包完成额度。这是兼容预算窗口，不冒充新协议的 Attempt 或共同提名。

等待按先到先服务处理；过期250ms的控制包不再注入。捕获退役先暂停控制发送，旧 capture 代次的在途许可不能作用于新句柄。IPC 失联使该传输退出，父进程的 Job 管理回收。正式 `MeshPeerTransports`、监听入口和 `MeshRouter` 传递控制所有者信息，避免同一控制包在上层和原生处重复扣预算。

业务包继续直接发送，不等待控制管道、不重传、不按跨数据报序号等待。HTTP 前导实际注入后仍保留原约32ms等待，HTTP/bare重叠序号及现有数据 profile 不变。`SLGQ1` 是有界、可合并的本地排队/拒绝统计；`SLW1` 继续只报告成功注入 API 调用，二者分开。

## 本次证据

| 产物 | 结果 | 证明范围 |
|---|---|---|
| `out/m3-legacy-control-30-20261013.json` | Pass，30轮、460项检查 | 实际 Windows named pipe、PID/授权/EOF、真实 C++ 的 FakeTCP+HTTP与UDP、双向1280B内层IP经MeshRouter、实际控制等待时业务仍通过、HTTP间隔、原生队列报告 |
| 同产物的八个逻辑所有者 | 每个获得20次许可，共160次 | 同一机器上的共享定时器与控制预算公平性；不是八台终端 |
| `out/resume-legacy-native-wire-20261013.json` | 69项 | 原生注入统计及失败日志接收者隔离 |
| `out/resume-legacy-parent-wire-20261013.json` | 51项 | 父端解析、单调计数及账本 |
| `out/resume-protocol-20261013.json` | 11项 | 旧 HTTP/SEQ profile |
| `out/resume-connections-20261013.log` | 81项 | 正式兼容连接、取消、恢复及资源清理 |
| `out/resume-managed-router-20261013.json` | 222项 | 受管路径与迁移原有回归 |
| `out/resume-windows-20261013.log` | 100项 | 隔离 Windows 生命周期、配置及界面反馈 |
| `out/resume-mesh-20261013.log` | 40项 | 八成员上限、成员鉴权及禁止成员转发 |

30轮原始 JSON 的 SHA-256：`911EA7B2B8F35441CEF476D3CD7CA20135978013D74ECE4817FAD388E2161E73`。
当时生产 backend SHA-256：`F7EB3FFF7B70B79D582CF756CA2CEA54F34B65AFDCF4CD38AA6B211E291ED460`；独立协议测试 backend：`D8DDB8DB541619E51E2ACE4C34EDF3C54E0BF3DC4194FF207DF8EAACA9DE801F`。该轮来源为 `f563e6e` 加本提交前未提交改动；正式包须从准确提交重新构建。

复现：

```powershell
dotnet run --project tests/StreamLink.LegacyControlTests -c Release -- --native out/native/udp2raw-protocol-test.exe --output out/legacy-native-control.json --rounds 30
```

初次负例产物和日志保留在 `out/m3-legacy-control-*`：夹具缺少IPv4校验和、UDP端口分配冲突及公平等待受线程唤醒顺序影响。前两项修正夹具，第三项修正实际准入控制器；没有降低公平性门槛。错误调用原账本测试缺少 `--native-report` 的执行记录也保留，随后按正确命令通过。原始调试日志不发布，其中含测试协议的加密调试输出。

后续本地夹具改用固定组件路径，私有会话仍独立。已观察到此前随机Temp exe路径留下多份Windows用户入站阻止规则；固定路径减少逐轮新应用通知和规则副本。夹具先核对backend，拒绝以生产WinDivert二进制运行Local测试。不删除既有阻止规则、不增加防护排除。

## 验收边界

该30轮使用回环UDP承载原始IP报文和内存IP适配器，没有加载物理WinDivert/Wintun，不证明公网NAT穿透、物理RST或八真实Windows公平性。模拟其他控制器耗尽额度的测试没有向公网发起压力流量。

helper内核自动ACK等开销只通过查询准入间接限制；线上完整审计仍未通过。排队和许可不代表网卡交付或对端收到。兼容业务pacing、真实出口变化、安装包恢复及公网质量Gate仍需独立推进。M0—M9总Gate保持NotPassed。
