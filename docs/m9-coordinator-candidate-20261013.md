# M9：独立协调候选的准备与 Linux 本机验证

没有切换现用公网入口。只读检查确认 streamlink-coordination 运行 /opt/streamlink-coordination/0.3.0-20261010172404/StreamLink.Discovery，回环 42861、PID 3676373；原 discovery 服务同时保留。当前 /health 仍为 protocol 3 / metadataProtocol 2 / shortPairing true / relay false，未声明新版 mesh/watch 能力。

从准确 git archive f2b3594 构建了 0.5.4 linux-x64 自包含单文件候选，二进制 101,586,205B，SHA-256 EACCA4FD49947F3B7878188374C2A6BA4B32446A80FC1AC6C952006DA444D01F。源码归档 SHA-256 F60F1F96A5B5BBD013C831A9CBE31B1512692B33E703C6420BC297426D890404。后续 Windows 诊断调度修复不在此候选中，最终协调包须在最终提交重新绑定，不能混写来源。

候选在 /opt/streamlink-coordination/candidate-0.5.4-f2b3594-20261013，使用临时 systemd 单元、专用既有服务账号、独立空数据目录和 HTTPS 回环 42864。RuntimeMaxSec 1800、内存 512MiB、ProtectSystem strict；临时测试证书仅用于此进程，未安装系统信任。现用数据目录、Cloudflare Tunnel、42861、旧服务均未修改。

启动 SSH 本地端口转发被自动审批以 blocked by policy 拒绝，转发未启动。改用服务器本机自包含测试程序，不重试该转发。

已通过：

- 实际候选 /health：meshProtocol 4、meshWatch 1、meshTraversal 1、maxMembers 8、relay false；未配置原始 SYN 观察器，tcpSynObserver 0。
- 37 项短码/密码/状态检查，含对实际 HTTPS 候选执行配对、批准和清理。
- 7 项实际 Linux API 检查：固定证书指纹、认证 watch、独立诊断/备用/自动质量能力、签名加密公告、签名备用 Offer、旧端未声明自动选路时不授权、管理员签名扩展成员、错误授权被拒。

全部业务数据测试均未经过此服务器。上述只证明候选控制 API，不证明公网打洞、八真实 Windows 或 WinDivert/Wintun。测试完成后临时候选服务已停止，现用 3676373 保持 active、原健康响应未变。

本机证据：artifacts/m9-coordinator-candidate-build-receipt-20261013.json、m9-coordinator-054-pairing-20261013.log、m9-coordinator-054-control-20261013.json、m9-coordinator-candidate-stopped-20261013.log。最初独立 API 测试源码位于 out/Coordinator054Checks，后续将通用复现入口加入 tests/StreamLink.CoordinatorCandidateTests（仅接受明确的回环 HTTPS 端点、证书指纹和结果路径）；含机器路径及测试证书的 out 目录不进入源码归档或 GitHub验证附件。

后续交付需补准确最终提交的协调候选、当前单元/数据备份及只恢复本服务的回退操作，核对旧客户兼容后再沿现有授权部署。现在未执行公网服务切换，也未替换任一 Windows 现用服务。
