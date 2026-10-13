# SEC-01：完整原生 TCP 解析器修复

基线：`3b285f2`，本轮规格提交 `61aa883`。修改真实 `recv_raw_tcp`，先验证 TCP 最小 20B 和声明头长，非法输入一律负返回、`payload=nullptr/payloadlen=0`；IP/TCP/选项解析使用局部状态，全部成功后才提交。未知选项超过剩余空间、时间戳格式错误现在拒绝，不再忽略选项解析错误。初始化旧客户端接收输出作为额外防线。

独立测试目标 `udp2raw-parser-test` 链接全部真实原生源码并直接调用 `recv_raw0`，向既有原生接收缓存提供离线帧；没有复制解析器或 IP stub，不开 socket/驱动。测试入口仅编入专用目标，发布目标不具备该入口。第一次夹具漏 Winsock 初始化导致 RST 日志的 inet_ntop 断言退出，此失败原样保留；它是夹具初始化问题，不能当成公网可利用性证据。补初始化后未修改生产解析器的基线确定性失败，再修复生产函数。

修复前 25,307 项断言中 7,901 失败；修复后零失败，包含 20,000 个固定种子的离线突变、IP 0–19B 截断、全部 TCP doff、TCP 最小载荷、选项越界、错误 IP 长度/协议、合法 HTTP/bare。断言数不等于独立网络场景或模糊测试穷尽。原有 SO 630 项状态用例以及 11 项完整协议回环测试通过。HTTP/bare SEQ、约 32ms 前导时序、有效加密和业务数据报语义未修改。

失败输出、接收状态、返回契约通过完整生产函数验证。legacy capture 与 broker 都将入站缓存交给该函数；受管入口另有最小头长/tuple 防线，选项仍由同一原生函数处理。当前不声称已完成独立物理 WinDivert 异常帧注入、线上 RST 或公网攻击可利用性验证；这些作为后续 Windows I/O/NET-01 证据继续处理。

证据在 `evidence/sec01/`：修复前后 JSON/日志、Ctest、SO 模型和完整协议回环结果，包含实际专用测试二进制 SHA-256。构建命令为 `cmake --build out/native --parallel 4`；验证 `ctest --test-dir out/native --output-on-failure` 和 `py -3 tests/protocol_loopback.py`。checksum/offload、分片及其余输入面由独立 SEC-02 处理，不将本次最小修复冒充完整安全审计。
