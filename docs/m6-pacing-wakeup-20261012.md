# M6：Windows pacing 唤醒与有限突发

开发基线 `a797d7e`。本次修复受管出口在 50 Mbps 配置下持续低于 49 Mbps 的本地性能缺口。**pacing 仍默认关闭；这里只通过本地调度吞吐门槛，未通过公网质量或默认启用 Gate。** 不修改 HTTP/SEQ、业务重传语义、现用服务或网卡配置。

## 测量与选择

改动前，原代码三次 3 秒重复测试中，单成员 47.890–48.087 Mbps、七成员 46.884–48.043 Mbps，均未达到原有 98% 门槛。初始 6144B 桶在 50 Mbps 下只容纳约 0.98ms 信用；有持续队列时，线程稍晚唤醒就会截掉额度。实测累计截断量与吞吐缺口相符。这是本地调度测量，不能归因于运营商 QoS。

只把桶扩大至 12288B 仍不足。随后按交替顺序测量两种桶容量、两种线程优先级，每种组合单/七成员各三次，每次 3 秒；没有修改系统定时分辨率、进程优先级或 CPU 亲和性。

| 桶容量 / 发送线程 | 单成员 Mbps 范围 | 七成员 Mbps 范围 |
|---|---:|---:|
| 6144B / Normal | 43.639–46.582 | 39.891–44.586 |
| 12288B / Normal | 46.368–48.268 | 47.859–48.878 |
| 6144B / AboveNormal | 48.832–49.129 | 48.912–49.520 |
| 12288B / AboveNormal | **49.869–49.979** | **49.796–49.907** |

这些是当时这台 Windows 的观测范围，含背景负载波动，不是所有硬件的性能保证。三秒观测用于对照选择，后续另做 20 秒验证。

## 产品改动

- `EgressPacer` 的独立发送线程采用 `AboveNormal`，继续使用高精度 waitable timer 阻塞等待，不忙轮询。未提升整个进程或其他线程的优先级。
- 桶容量按约 2ms 配置速率取完整 1536B 单位，最少 4 个、最多 8 个。50 Mbps 时为 12288B，10 Mbps 仍为原来的 6144B。迟到唤醒丢失的额度不会无限累积或事后突破桶上限补偿。
- 字节公平调度、20ms/1MiB 排队容量、有限控制优先权、单个数据报上限与取消语义不变。突发容量和队列容量是两项不同限制。
- 状态增加 `BurstBytes`、`WorkerPriority`；正式 Runner 日志显示实际突发上限。原有等待时间、令牌截断、溢出和队列年龄保留。
- A/B 构造参数仅供内部测试使用。公开配置仍只有原有的外层 Mbps，`ManagedEgressMbps=0` 关闭。
- 测试收尾改为先关闭 flows，再等待整个调度线程退出，随后比较发送事件与最终计数。之前只等待回调结束，偶尔早于统计提交，造成字节校验竞态；原始失败产物保留。
- 打包回归加入出口生命周期、同 socket 与队列正确性检查；吞吐实验仍单独报告，不能用 `--correctness-only` 冒充性能通过。

Windows 的高精度计时器和线程优先级是不同机制；设置前者不保证线程立即获得 CPU。实现使用 [CreateWaitableTimerExW](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createwaitabletimerexw) 的高精度标志，以及相对进程的 [AboveNormal 线程优先级](https://learn.microsoft.com/en-us/windows/win32/procthread/scheduling-priorities)。它不是实时调度保证。

## 本轮证据

全部产物位于 `artifacts/`；代码与构建哈希见 `m6-pacing-wakeup-receipt-20261012.json`。

| 产物 | 结果与范围 |
|---|---|
| `m6-pacing-baseline-20261012-{1,2,3}.json` | 原代码性能均 Fail，保留基线 |
| `m6-pacing-burst-study-initial-20261012.json` | 初始 A/B，包含最终计数竞态失败，未覆盖为成功 |
| `m6-pacing-burst-study-20261012.json` | 4/8 单因素交替观测；StudyOnly，均未达到吞吐目标 |
| `m6-pacing-priority-study-20261012.json` | 24 个对照样本；StudyOnly，逐样本报告吞吐、CPU、间隔、包络与截断量 |
| `m6-pacing-sustained-20261012.json` | **28 检查通过**；单/七成员各 20 秒为 **49.809 / 49.871 Mbps**，原 49 Mbps 门槛不变 |
| `m6-pacing-broker-off-20261012.json` | 真实 C++/管道/MeshLink/Router，两个方向各 20 秒；pacing 关闭，约 **49.960 / 49.961 Mbps**、最终计数丢失 0 |
| `m6-pacing-broker-on-20261012.json` | 同源代码链路，50 Mbps 内层负载，**60 Mbps 外层**限额；约 **49.932 / 49.961 Mbps**；资源正确退出，质量结果见下文 |
| `m6-pacing-runner-20261012.json` | **117 检查通过**；正式工厂/Runner 的 FakeTCP 和 UDP、IPv4/IPv6、能力降级与关闭清理；实际 C++、helper、HTTPS、UDP，raw/IP 仍为内存适配 |

20 秒调度验证使用真实 Windows 计时器与合成持续积压发送端。进程 CPU 分别为 1.391/1.422 秒（约一核 7%），不是整个 StreamLink 数据面 CPU；全部速率和突发包络检查通过，七成员按字节公平。关闭后队列为零。额外的满载新成员测试在 **0.818ms** 首次发包，一秒内新旧成员分别发送 3160500/3162162B，没有扩大排队容量。

发送回调时间戳的包络校验包含一个最大数据报的执行边界余量；实测超出线性速率的最大字节量分别为 12338/13557B，均在 `12288 + 1466` 范围内。不能把令牌桶内部容量误报成无执行误差的物理线路突发测量。排队容量也不是延迟硬保证：调度用例最大队列年龄仍达到约 55.3/33.4ms。

### 真实 native 链路的收益与代价

负载链路使用三个逻辑成员和四个真实原生进程，同一源捕获所有者接两个 peer；原始包与内层 IP 适配器是内存实现。开启实际 wire 控制预算。两个方向是单设备向两端、两端向单设备顺序发送，不是三台真机。50 Mbps 按完整 1280B 内层 IP 包计量，尚不是应用净荷或真实串流码率验收。

| 方向 | 关闭 pacing：内层 Mbps / 本机 P95 | 开启 pacing：内层 Mbps / 本机 P95 | 开启后的丢失 |
|---|---|---|---|
| 单出口 → 两端 | 49.960 / 6.073ms | 49.932 / 14.188ms | **57 包，0.0584%** |
| 两端 → 单设备 | 49.961 / 5.972ms | 49.961 / 7.110ms | 0 |

57 包全部对应 pacer 的队列溢出，fixture/raw/capture/router 队列丢失为零。原有发生器最多追赶 128 个完整内层包，包含外层后可超过该出口 150000B 队列容量；此测试保留原负载方式，不扩大队列来隐藏溢出。该解释不等于已证明每次溢出的唯一时序原因。

开启后单出口方向 P99 从 8.374ms 增至 17.889ms，两个方向最大延迟约 36.76/18.63ms；managed CPU 时间也有增加。这些是同一台机器的单调时钟端到端采样，包含整个受控业务链，不能当公网单向延迟或 RTT。统计含 500ms 收尾，不能替代期限内送达指标。

**因此不默认启用。** 完整链路的峰值输入、队列与尾部延迟、WAN A/B、60 分钟负载、多出口与全管线合计容量仍待验证/实现。pacing 没有替代拥塞控制，也没有解决严格 NAT 的可达性。

## 复现与回退

```powershell
dotnet build tests/StreamLink.EgressTests -c Release
dotnet tests/StreamLink.EgressTests/bin/Release/net10.0-windows/StreamLink.EgressTests.dll artifacts/pacing-study-new.json --priority-study
dotnet tests/StreamLink.EgressTests/bin/Release/net10.0-windows/StreamLink.EgressTests.dll artifacts/pacing-sustained-new.json --sustained
dotnet build tests/StreamLink.EndpointPoc -c Release
dotnet tests/StreamLink.EndpointPoc/bin/Release/net10.0-windows/StreamLink.EndpointPoc.dll --broker-load out/native/udp2raw-protocol-test.exe --mbps 50 --seconds 20 --rounds 1 --output artifacts/pacing-broker-new.json --egress-mbps 60
```

负载前先完成当前源码的 `scripts/Build.ps1`，确保协议测试原生程序匹配。独立测试应顺序运行，并记录背景负载；不要与用户串流争用资源。命令不加载 WinDivert/Wintun，不改变现用网络。

设置 `ManagedEgressMbps=0` 后重新启动该网络即可关闭实验调度，回到原发送路径。代码回退基线为 `a797d7e`；现有安装候选和现用服务尚未更新。本次不宣称 M6 或 M0—M9 全部完成。
