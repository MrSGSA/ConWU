# SEC-02：接收校验与故障隔离首批证据

默认保留 WinDivert 原有按 checksum metadata 的 offload 归一化，随后严格拒绝仍错误的 TCP checksum。IPv4 未重组分片不进入运输解析；IPv6 只接受当前支持的固定 TCP 头，扩展头/分片/jumbo 不假定偏移。受管入口同步校验 TCP 选项，坏输入/归一化失败丢弃该帧，不再通过抛异常终止整个 capture owner。有效 HTTP/SEQ 与发送路径未修改。

核对官方 v2.2.2 对应源码 `sys/windivert.c`：出站 checksum 标志源于 Transmit offload 请求，入站源于 Receive ChecksumSucceeded；不能将一个清零标志直接当成线上坏包，也不能忽略最终可计算的错误 checksum。依据 [官方文档](https://reqrypt.org/windivert-doc.html) 的 metadata 与注入约束保留现有归一化，再做严格校验。该源码核对不是物理 offload 抓包 Gate。

本轮完整生产解析器 29,659 项断言 Pass，含 20,000 个固定种子突变、IPv4/IPv6 最小头长及 doff、错误选项/checksum、分片/扩展/jumbo拒绝和成功/失败状态契约。22,414 帧同一语料由 C# tuple/选项/checksum 校验复核，743 接受、21,671 拒绝、零差异。11 项既有完整 HTTP/bare/GRO/损失/认证回环通过。证据与实际语料、测试二进制、官方依赖源码 hash 在 `evidence/sec02/`；语料可由专用 test 目标的 STREAMLINK_PARSER_CORPUS 环境变量重生成，不在生产目标启用。

目前只执行 Windows 原生离线解析和 C# 校验，没有据此声明 ASan/UBSan、独立物理坏 checksum/offload、WinDivert 异常流或完整输入/依赖安全审计已通过。现有 LLVM 有 ASan DLL，但当前 MinGW 产品不是可直接套入 MSVC 工具链的项目；后续按实际可运行的 sanitizer 工具链补证据，不把库文件存在当测试已运行。SEC-02 保持 InProgress，后续 SBOM/其余输入面和真实 I/O 继续补齐。

## 后续补充：完整公共解析器 sanitizer

2026-10-13，既有 ArchLinux WSL2 中 GCC 16.1.1 实际构建完整 Linux 原生入口与公共生产解析器，ASan＋UBSan＋leak detection运行29,659断言（含20,000突变）通过。脚本 `scripts/Test-NativeParserSanitizers.sh` 不打开raw socket或驱动。首次构建漏 libev include 失败保留，补入仓库已有 libev 后通过。此结果增加公共解析代码的 sanitizer 证据，不是 Windows capture、broker 或 WAN sanitizer。

同时补齐 packet_info/raw_info 的确定性字段初值，保留既有构造函数的随机TCP ISS；避免事务性解析复制未初始化bool等字段。随后 Windows Ctest（完整parser与SO）和11项协议回环重验通过。运行/源码/二进制hash在 `evidence/sec02/sanitizers.json`。尚未完成的物理offload与依赖审计继续留在任务账本。
