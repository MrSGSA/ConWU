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

发现任务可取消等待持久化回执，但仍遵守先保存 PKARR 序号再发布。链路从已连接转为断开时立即通知发现任务，打断健康连接最长 60 秒的刷新休眠，及时重新交换候选和参与协调。关闭后台要等任务和 helper 退出、清空资源持有表后才报告成功；等待超时向 SCM 返回失败状态。协调监听重配同样先取消连接并等待退出，只改外部诊断地址不重启监听。

TCP／HTTPS 的协调主动建连复用 STUN 观察连接的完整本地端点，固定源 IP 和端口，避免对端路由重新选网卡。相对探测时间按请求往返耗时估计回程延时；首次辅助的过期调度可由绑定令牌和来源的参与方请求重新同步，同一邀请最多安排三轮。迟到的旧轮次报告不会替换新轮次，候选、模式与配对承诺不随重试改变。主机得到直接配对的公钥揭示后停止辅助轮询。已配对成员在请求调度前预留建连锁，并持续持有到定时探测完成，防止普通重试抢占同源资源；同一轮次只启动一次任务。成员调度提前八秒安排，错过有效窗口后可在 boot 和候选不变时生成新轮次，健康通道继续停止辅助探测。

网卡以 1280 MTU 读写，每轮最多批处理 64 包，内部队列有界。TCP/HTTPS 分流使用 CWF1 身份握手与 FIFO fence；辅助连接退出后回到主连接。原始承载按数据报传输，不因此获得 TCP 可靠重传。

高级协调首次辅助和已配对成员辅助均包含两端主动发起的探测，服务器交换候选并安排轮次，主机／从机角色不限定 TCP 发起方向。当前六种承载的外层均为真实 TCP 或 TCP 外观，不能据此推定通用 UDP 双端打洞已实现。下一阶段在保持默认模式的前提下，抓包核实双方实际 SYN 与同源端点，再研究双端目标相关／随机端口 NAT 的碰撞和状态跟踪；实验清单见 `docs/后续计划.md` 的“高级协调模式的穿透极限”。

## 安全与兼容约束

配对状态将待审批 `pending` 与配置交付 `Delivering`、完成 `Completed`、拒绝和过期分开。决定后卡片与角标收尾，但内部房间保留用于交付／ACK 重试。无成员身份的申请可本地取消，不生成签名离网通知；正式成员的离网通知与授权规则继续保留。操作回执先读取完成标记，再取状态快照，避免返回“已完成”同时携带操作前的临时状态。

UU 设备状态采用 Unsupported／Disabled／WaitingNetwork／WaitingUu／Applying／Ready／Transmitting／Idle／Error，规则启用和实际流量确认分开。确认绑定当前规则代次；进程或已连接网络代次变化时清除旧确认、重建规则，失败按有界退避重试。历史计数仅保留现存获批网络，官方进程路径限制保留。Windows 规则是平台实现，规范状态与恢复语义可供未来 APK 复用，当前没有恢复安卓开发。

本地更新结果通过内容回执标识确认，确认记录单独保存，保留安装历史与维护／回退资料。后台运行期间可读取更新 worker 稍后落盘的最终状态；旧确认不能覆盖新下载或下一次安装结果。成功提示展示后自动收起，并提供手动关闭；错误保留供用户处理。

配对先交换承诺，再比较 SAS，并由主机审批；完整配置先落盘后确认。业务包须经过 AEAD、重放检查、当前路径挑战和虚拟源/目标地址检查。公网候选、STUN 或网关映射结果不构成授权，也不证明第三方一定能够入站。

PKARR 验证 BEP44 签名，checkpoint 的 sequence 与 digest 持久化，拒绝回退与同序内容冲突。公告包含加密 boot/ack 状态；业务不经过 PKARR 或协调端。DNS 查询不在应用内缓存，合并独立解析结果；可更新订阅失效时不会把首次入口偷偷作为旧地址备用。

实验 Store 拒绝非自有的非空目录、上级路径和重解析/符号链接祖先。Windows 私密资料使用 DPAPI 与本机 ACL，Linux 使用 0700/0600。原子写入只保留一个 previous。当前并未保证所有密钥中间值都被内存清零。

WebUI 仅 loopback，限制 Host/Origin，使用一次性入口票据、滑动会话和 CSRF。界面保持现有接口兼容，所以部分内部头仍带 `streamlink` 名称，不代表运行依赖旧后台。

默认服务为 `ConWURustExperiment` / `conwu-rust-experiment.service`；正式构建保留原 SCM / systemd 升级身份。验证 MSI 通过独立 GUID 分离服务、数据与产品标识。后台正常用户通过经 SCM PID 校验的本机管道访问 SYSTEM 服务，不获得私密目录权限。

下载核对官方来源、平台资产和 SHA-256；默认构建无法发起安装。Windows MSI 在文件覆盖前保存完整上一版，成功后登记完整 MSI 维护源；Linux 更新 worker 由独立 systemd 单元承载。更新完成检查后台、启用网卡及协调监听。回退不会自动倒退已经提交的签名撤销或 PKARR 序号。具体安装、实网与恢复证据见 VALIDATION.md / PARITY.md。
