# 相对空载 RTT 质量档

0.5.5 开发代码在原实验负载诊断上加入同路径空载基线。现用两端服务及协调服务未替换，默认仍 PreferFakeTcp；原有诊断、备用和自动选路许可没有改变。

## 判定与协议

计划的标准档使用 50Mbps 应用目标、有效收到吞吐至少 49Mbps、加载 RTT p95 相对空载增加不超过 20ms。新版规则按目标的 98% 判断实际接收吞吐，仍要求截止缺口不超过 0.1% 和有界到达波动。它不把接收收尾后的最终送达当作播放 deadline，也不报告没有时钟依据的单向延迟。

每个方向分别测 Active 与 Candidate，共四组空载基线。每组三个 5 秒负载窗口共享同一实际路径的基线，记录 4—8 个已匹配 nonce 的往返样本、p95 和本机年龄。基线年龄必须小于 30 秒，三窗的基线身份/数值一致；原有窗口仍关联 Lease、网络代次、路径、会话与成员方向。

开始负载前使用现有 MeshLink 同路径维护探针，最多八次、间隔至少 200ms；最少四个合法返回并经过 800ms 观察才开始发送。3.5 秒内拿不到样本就取消，不把普通旧 pong、错误路径或错误窗口的回复计为基线。探针经过原维护和全机预算，诊断总时长、总字节、唯一 source 和全机唯一会话上限保持原值。

`DiagnosticTiming=1` 是独立能力，依赖已经许可的 PathDiagnostics。两端的能力在加密签名公告中确认，还需要协调服务支持；所有者在 Attempt 创建时固定协商结果。SQD2 固定 192B 的版本 2 利用原保留区携带基线计数、RTT 与年龄，版本与字段在 AEAD 保护范围内。版本 1 会话仍拒绝这些字段；新会话也拒绝版本 1 报告，避免以另一套规则解释结果。

缺少任一端或服务能力时仍使用原绝对 RTT 诊断规则，质量状态明确为 LegacyDiagnostic。新版显示 RelativeIdleRtt；比较批准的摘要区分两种档案，不能将同一批准从一种规则复用到另一种。新增空载值默认不序列化，普通旧元数据和旧诊断摘要的规范形状保持。

## 验证入口与边界

```powershell
dotnet run --project tests/StreamLink.ManagedPathTests -c Release -- --relative-quality-only --output artifacts/relative-rules.json
dotnet run --project tests/StreamLink.ManagedPathTests -c Release -- --relative-session-only --output artifacts/relative-session.json
dotnet tests/StreamLink.MeshRunnerTraversalTests/bin/Release/net10.0-windows/StreamLink.MeshRunnerTraversalTests.dll --native out/native/udp2raw-protocol-test.exe --rounds 1 --output artifacts/relative-udp.json --relative-quality-udp-only
dotnet tests/StreamLink.MeshRunnerTraversalTests/bin/Release/net10.0-windows/StreamLink.MeshRunnerTraversalTests.dll --native out/native/udp2raw-protocol-test.exe --rounds 1 --output artifacts/relative-native.json --relative-quality-native-only
```

14 个规则/解析检查覆盖高空载 RTT 的正确准入、20ms 边界、49Mbps 下限、基线缺失/过期/NaN、三窗一致性、不同档案批准隔离和格式版本拒绝。最初 NaN 负例暴露了摘要序列化先于数值校验的异常，现已能形成诊断未知结果并拒绝资格；没有放宽网络解析边界。

180 个控制模型、600 检查覆盖合法/重复控制、普通旧返回、错误路径、错误窗口和无返回取消。旧控制 390 模型/1500 检查、旧质量 15 检查通过。152 个协商检查包含双方/服务能力缺失、签名公告和版本依赖。

正式 UDP 1Mbps 回环流程已经完成 12 个窗口，双端记录 TimingVersion=1、RelativeIdleRtt、每窗四个共享基线样本，形成一致摘要并保留质量相近的原 socket 路径。它使用实际 Winsock/HTTPS/Runner 和内存 IP 适配器，不能证明 WAN、50Mbps 或物理 Wintun。

原生同流程 14 项正式检查通过：实际 C++、helper、IPC 与 HTTPS，raw/IP 适配器仍为受控内存。双端记录 RelativeIdleRtt，诊断实际时长 88,459/88,882ms，保持原 90 秒共同上限；测到受控原路径损失后复用既有合格 tuple 完成共同选路，随后 11 次完整 IP 业务探测连续。该夹具的稳定区间起点距选择触发 107ms，确认时刻另计，不是 WAN/播放指标。

首次原生运行在 Leg11 达到 90,650ms 后按期限退出，记录为 Fail。源码随后让版本 2 收到已认证控制消息时立即推进响应，减少逐步骤等待 Heartbeat 的成本；没有扩大时长、字节、维护或控制包预算。失败日志和最终通过日志分别保留。

实际保留的 0.5.3 Core DLL 经过固定 SHA-256 核验，158 项新旧协商/签名/接口检查通过；这不是旧完整服务或公网混网验收。具体产物为 `artifacts/m6-relative-*.json` 和对应日志。未来 Package 已加入两个档案的控制、规则及正式两种承载检查，完整包验证和 60 分钟真实质量 Gate 仍未执行。
