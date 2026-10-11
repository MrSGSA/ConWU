# M9：0.5.0 候选包产物与双 Windows 只读校验

源码 commit：`65e8310`。后续文档提交不改变该包的来源。发布等级为 **development-candidate / NotPassed**，不是完整 M0—M9 验收通过版。

此记录为历史候选。原同名 ZIP、源码 ZIP、摘要和 preflight 已归档至 `artifacts/releases/history-65e8310/`，下文原文件名对应该归档；原 stage 和 Akane 目录保留。当前同名发布 ZIP 已由 [10 月 12 日刷新候选](m9-candidate-refresh-20261012.md) 替代，请按源码 commit/哈希区分。

## 本地产物

- `artifacts/releases/StreamLink-0.5.0-win-x64-preview.zip`：54,251,821 字节，51.74 MiB。
- SHA-256：`FF6913585B3CD7A09C0FD3199F818FCCF290C80D3B023163EAA213F78CBEDD58`。
- `artifacts/releases/StreamLink-0.5.0-source.zip`：对应准确源码 commit，SHA-256 `32BFF7EE85BCD92F2D4577AA274CA59C7257FE99F84FB1E7ECBD0A02E7525319`。
- 完整目录：`out/release-20261011-234156-b53eb9`，manifest 包含 281 个实际文件，生产 WinDivert 后端、版本、自包含运行时及组件检查通过。
- `artifacts/release-verification-0.5.0.json` 包含默认开关、尚未实现能力、失败及未执行 Gate，并已放入包内。没有把本地 Pass 转成完整 Release Pass。

`m9-package-0.5.0-20261011.log` 是完整构建/回归/首次打包；`m9-package-final-0.5.0-20261011.log` 使用同 commit 构建收据复核后补入验证摘要。`bundle-preflight-0.5.0.json` 由实际发布 EXE 校验，不依赖 `dotnet` 命令运行产品。

原有打包回归完成：原生协议、核心、配对、Windows 生命周期、调度与恢复、组网、UDP 基础、UPnP/PCP/NAT-PMP、界面渲染及本地 HTTPS 协调。各检查原始计数见日志，不与本轮不同范围/重复断言相加推导覆盖率。`m9-package-boundaries-20261011.json` 另确认协议测试后端被拒绝，以及源码 ZIP 不含构建/私有配置产物。

## Akane 上的实际候选程序

已限速传入用户指定工作区下的独立目录：

`E:\Codex_Workspace\Streamlink\candidate-0.5.0-65e8310\bundle`

远端 Windows 11 专业工作站版 `10.0.26300` 运行包内自包含 `StreamLink.exe --verify-bundle`，281 文件全部通过；zip hash 与本机一致。生产原生程序的只读 capability 查询返回 WinDivert、native ABI 1 和 IPv6 ABI 2。证据：`artifacts/m9-akane-bundle-20261011.json`。

测试前后原服务均为 `Running`，注册服务路径未改变。本次不安装服务、不打开驱动、不创建网卡、不进行业务/打洞测试，因此它只证明传输完整性及发布程序在第二台 Windows 上的只读启动，不证明服务升级、回滚或公网性能。

只读环境检查还发现 Akane 有原生全局 IPv6，Thinkbook 没有；双端公网 IPv6 Gate 仍缺前提。公网控制服务器 SSH 本次已可达，协调服务 active；未替换其服务。

## 仍未完成

完整状态仍以 `execution-status-20261011.md` 为准，尤其是严格 NAT 增强、全部资源/控制包账本、质量 Gate、真实八机、协调中断、无人登录冷启动和已安装包升级恢复。出口 pacing 的七 flow 性能 Gate 失败保持可见，默认 0。

候选目录可保留供后续隔离测试。正式安装会重连，必须按具体验证与回滚操作推进；现用版本仍保留。回滚说明在包内版本更新说明及 `docs/releases/v0.5.0-preview.md`。
