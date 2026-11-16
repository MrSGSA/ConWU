# Rust 架构

## 边界

`conwu-core` 不依赖网卡、后台服务或 UI，负责兼容协议及身份验证。`conwu` 是单个原生桌面后台，嵌入现有 WebUI，通过平台适配层管理网卡与独立承载进程。正常运行无需 CLR。

```text
WebUI / CLI
    │ loopback + session + CSRF
    ▼
后台命令与事件 ─── 独立网络配置 / 私密 Store / 日志
    │
    ├── 配对：直连码 → ECDH 承诺 → SAS 审批 → 落盘回执
    ├── 发现：TXT/HTTP 订阅、PKARR、可选协调、网关映射
    └── 数据：TUN/Wintun ↔ MeshLink AEAD ↔ 六协议承载
```

## 主要模块

| 文件 | 职责 |
| --- | --- |
| `conwu-core/identity.rs` | 设备与网络身份、签名目录、成员撤销、虚拟 IP 与 Slot 分配 |
| `conwu-core/pairing.rs`、`code.rs` | SLP1、SAS、分片、IPv4/IPv6 直连码 |
| `conwu-core/crypto.rs`、`link.rs` | P256、HKDF/HMAC、ring AES-GCM、SLM4/CNW1、防重放 |
| `conwu-core/metadata.rs`、`departure.rs` | 加密公告、目录 successor、签名离网与回执 |
| `conwu-core/stream.rs`、`rendezvous.rs` | CWF1 分流协商、PKARR 加密重连状态 |
| `backend.rs`、`model.rs` | API、命令幂等、配置事务、网络选择、审批与状态 |
| `runtime.rs`、`flow.rs` | 网络任务、路径挑战、暂停保活、三连接分流和故障收敛 |
| `transport.rs`、`raw.rs`、`adapter.rs`、`routes.rs` | TCP/TLS、原生进程桥接、TUN/Wintun、现有地址与路由冲突检查 |
| `discovery.rs`、`dns.rs`、`pkarr.rs` | 无应用 DNS 缓存、多解析器、订阅、BEP44 DNS TXT 与序号检查 |
| `coordinator.rs`、`assistance.rs` | 可选本机协调、签名 watch / traversal、TCP STUN、候选交换、同步探测与外部 HTTPS 源站诊断 |
| `gateway.rs` | PCP / NAT-PMP / UPnP 的自有映射申请、续租和删除 |
| `store.rs`、`logging.rs` | 原子持久化、独占锁、DPAPI/ACL、轮转日志与脱敏 |
| `web.rs`、`tray.rs`、`platform.rs` | 嵌入式 WebUI、托盘、独立实验服务 |
| `uu.rs` | Windows UU 自动匹配直连网络、进程身份与 WinDivert 接管 |
| `updates.rs`、`updater.rs`、`migration.rs` | 官方源检查与下载、受 feature 约束的本地安装、只读旧配置导入 |
| `installer.rs`、`maintenance.rs`、`recovery.rs`、`instance.rs` | MSI 事务、完整上一版及 MSI 维护源、快照边界与隔离 / 正式产品身份 |

## 生命周期与并发

数据库写操作与配对事件通过事务互斥处理。检查更新、下载、只读入口解析等长 I/O 独立执行，不占住整个命令队列。`operationId` 与请求摘要绑定，重复请求返回同一结果；创建与加入的摘要落盘，后台重启后的重试也不会新建第二条网络。

每个网络保存独立身份、设置、发现状态、网卡、取消令牌及路径。新建网络避免监听/源端口冲突和虚拟网段重复。更改监听策略时先等待旧监听和子进程退出；删除最后一个使用者后释放监听。普通元数据变化不会重建 AEAD 状态或中断已有路径。

Windows Wintun 使用按网络独占的代次日志和新 GUID，复核旧 PnP 节点及接口归属；遇到已关闭接口的类配置缓存时，沿用原版的条件等待和一次新 GUID 重试。IP 与 MTU 通过 IP Helper API 配置。设备初始化在阻塞线程中执行，并检查后台取消信号。只有记录中已确认归属且 PnP 已移除的接口可从冲突检查中排除。

从原版导入的网络还会保存 `legacyAdapter` 所有权范围，继续使用原来的 `StreamLink-Wintun` 排他锁、代次日志及网卡名称和类型。Rust 与原版因此能识别彼此已关闭的网卡，也不会同时占用同一网络；新建网络使用 ConWU 自有范围。交接不需要启动旧后台，也不会删除共享驱动或接管外来接口。

发现任务可取消等待持久化回执，但仍遵守先保存 PKARR 序号再发布。关闭后台要等任务和 helper 退出、清空资源持有表后才报告成功；等待超时向 SCM 返回失败状态。协调监听重配同样先取消连接并等待退出，只改外部诊断地址不重启监听。

网卡以 1280 MTU 读写，每轮最多批处理 64 包，内部队列有界。TCP/HTTPS 分流使用 CWF1 身份握手与 FIFO fence；辅助连接退出后回到主连接。原始承载按数据报传输，不因此获得 TCP 可靠重传。

## 安全与兼容约束

配对先交换承诺，再比较 SAS，并由主机审批；完整配置先落盘后确认。业务包须经过 AEAD、重放检查、当前路径挑战和虚拟源/目标地址检查。公网候选、STUN 或网关映射结果不构成授权，也不证明第三方一定能够入站。

PKARR 验证 BEP44 签名，checkpoint 的 sequence 与 digest 持久化，拒绝回退与同序内容冲突。公告包含加密 boot/ack 状态；业务不经过 PKARR 或协调端。DNS 查询不在应用内缓存，合并独立解析结果；可更新订阅失效时不会把首次入口偷偷作为旧地址备用。

实验 Store 拒绝非自有的非空目录、上级路径和重解析/符号链接祖先。Windows 私密资料使用 DPAPI 与本机 ACL，Linux 使用 0700/0600。原子写入只保留一个 previous。当前并未保证所有密钥中间值都被内存清零。

WebUI 仅 loopback，限制 Host/Origin，使用一次性入口票据、滑动会话和 CSRF。界面保持现有接口兼容，所以部分内部头仍带 `streamlink` 名称，不代表运行依赖旧后台。

默认服务为 `ConWURustExperiment` / `conwu-rust-experiment.service`；正式构建保留原 SCM / systemd 升级身份。验证 MSI 通过独立 GUID 分离服务、数据与产品标识。后台正常用户通过经 SCM PID 校验的本机管道访问 SYSTEM 服务，不获得私密目录权限。

下载核对官方来源、平台资产和 SHA-256；默认构建无法发起安装。Windows MSI 在文件覆盖前保存完整上一版，成功后登记完整 MSI 维护源；Linux 更新 worker 由独立 systemd 单元承载。更新完成检查后台、启用网卡及协调监听。回退不会自动倒退已经提交的签名撤销或 PKARR 序号。具体安装、实网与恢复证据见 VALIDATION.md / PARITY.md。
