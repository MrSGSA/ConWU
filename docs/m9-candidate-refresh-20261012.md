# M9：10 月 12 日开发候选刷新

本次包准确对应 `f648059ab1de6e9d7aeec9e7d9e26e9deeb23f3b`，包括 `6c5a121` 条件预测/短窗口观察、`31f8ff7` 原生控制包计账、`68ba76e` 签名撤销恢复处理。本文及随后状态文档提交不改变包的源码来源。

**版本仍为 0.5.0-preview，development-candidate / releaseGate=NotPassed。** 尚未完成整个 M0—M9，也未将实验能力变成默认。

## 实际产物

| 文件 | 信息 |
|---|---|
| `artifacts/releases/StreamLink-0.5.0-win-x64-preview.zip` | 54,268,678 字节，51.75 MiB；SHA-256 `01D319810AB6E21B961404ECBF1615D742C66DEC4F9205AF6A6EB88E3FDC1B1D` |
| `artifacts/releases/StreamLink-0.5.0-source.zip` | 同一已提交源码；SHA-256 `C12D2577A7045A8273A5735926F0EF6EDDAD81D4E40FAC7019C3165061B67611` |
| `out/release-20261012-021940-790131` | 完整自包含 Windows x64 目录；manifest 覆盖 281 个文件，原生 `wireControl=1` |
| `artifacts/releases/history-65e8310/` | 保留旧候选 ZIP、源码 ZIP、校验和、验证摘要及 latest/preflight 元数据；旧完整 stage 与 Akane 旧候选目录也未动 |

新增打包来源保护：验证摘要必须与当前 commit、版本和候选发布等级完全相符。真实 `Package.ps1 -SkipBuild` 入口已确认拒绝旧 `65e8310` 摘要，拒绝发生在构建和 stage 前。随后使用正确摘要从头构建，没有跳过测试或借用旧收据。

## 本轮验证

`artifacts/m9-package-refresh-20261012.log` 记录完整打包回归：原生 profile、核心、配对、Windows 生命周期、连接调度/恢复、MeshLink、UDP、预测模型、TCP 观察、网关协议、界面渲染和本地协调测试均以成功退出完成。各范围仍以具体测试说明为准，不把断言总数或重复回归当成实际 NAT 覆盖率。

生产后端、版本、官方驱动签名、固定 Wintun 哈希均经过既有打包校验。实际包内自包含 EXE 的 `--verify-bundle` 在本机通过，281 文件；没有依赖系统 `dotnet` 来启动产品。源码/安装 ZIP 文件名边界检查未发现构建缓存、临时私有配置或密钥文件；这项检查不是源码内容秘密扫描。

本次重要证据文件：

- `artifacts/m9-stale-summary-rejection-20261012.log`
- `artifacts/m9-package-refresh-20261012.log`
- `artifacts/bundle-preflight-0.5.0.json`
- `artifacts/m9-refresh-archive-boundaries-20261012.json`
- `artifacts/m9-akane-refresh-20261012.json`
- `artifacts/release-verification-0.5.0.json`：已随包包含默认启用项、未实现项、失败和待验证 Gate，以及相关证据哈希。

## Akane 独立目录

新候选位于用户指定工作区：

`E:\Codex_Workspace\Streamlink\candidate-0.5.0-f648059\bundle`

以 8Mbps 上限复制 ZIP，远端核对完整 SHA-256，并使用实际包内 EXE 只读验证；281 文件通过。检查前后原服务均为 Running，注册路径都为原有 `0.3.2-9f9694aed3` 安装目录。新候选没有安装服务、打开驱动、创建 Wintun 或进行业务测试。

这证明传输完整性与两台 Windows 上的只读程序启动，不证明已安装包升级、回滚、冷启动或新协议公网业务成功。现用连接没有切换到该包。

## 默认能力、未完成项与回退

默认仍是兼容显式 TCP 入口、udp2raw FakeTCP+HTTP、Wintun/MeshLink、PreferFakeTcp，禁止服务器或成员业务中继。原生 SO、UDP 降级、TCP SYN 诊断、网关控制、外层 IPv6、pacing 均需原有显式条件。预测资格/短窗口不会自动生成预测候选；概率策略和 AutoQuality 尚未开放。

正式校准/预测候选协调、有界概率增强、完整内核/兼容实例计账、多出口队列与质量策略仍需实现。真实公网 SO/UDP 正例、物理 I/O/PMTU、八台真实 Windows、60 分钟负载、物理网络六分钟控制中断、无人登录重启和已安装升级/回滚验收仍未通过；历史七 flow pacing 48.876Mbps 的失败保持可见。

当前无需回退运行服务，因为没有升级它。测试这个候选时应保留原完整包和配置，用设置中的安装流程部署；不能只替换 EXE。撤回实验可关闭对应设置，pacing 设为 0；整包退回按版本更新说明先停止网络、等待所有者清理，再从旧完整包安装后台，不能倒退成员授权 revision。

后续继续开发，详细状态以 [执行状态](execution-status-20261011.md) 为准。当前包没有推送 GitHub Release，也未宣称正式发布验收完成。
