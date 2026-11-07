# ConWU Linux 候选包

版本和验证范围以随包清单及报告为准。主命令为 `conwu`；保留 `streamlink` 兼容命令、`streamlink.service` 和产品数据目录。本版双机多网络目录和接收协议与旧版不兼容，双方及协调设备应同步更新。Cloudflare 配置及限制见 [DDNS 说明](../../docs/aq1/ConWU与Cloudflare-DDNS-20261106.md)。

同一程序可以参与组网、提供 HTTPS 协调服务，或同时承担两项功能。默认 FakeTCP＋HTTP，不自动改走 UDP。协调服务默认关闭，不会自动开放公网端口。

本包为 x86_64 / glibc 自包含包，内含 .NET 10 运行库与静态链接原生传输。实际验证的平台和网络条件以随包报告为准；不能把隔离命名空间测试视为真实 NAT 或长时间串流验收。Alpine/musl、ARM64 不适用此包。

参与网络需要 Linux TUN、iproute2、nftables、iptables（可使用 nft 后端）以及 root 或相应的网络管理权限。仅提供协调服务不需要这些网络组件。WebUI 不依赖 Linux 图形环境。

## 安装和更新

解压后执行 `sudo ./install.sh`，安装为 `streamlink.service` 并启动。`--no-start` 只安装，不立即运行。旧服务先停止，再切换程序；普通安装保留 `/var/lib/streamlink`。若旧网络配置不兼容，新版会提示重新设置，不能假定旧权限已迁移。原程序保留在 `/opt/streamlink/releases`；启动失败会尝试恢复原版本。

本轮需要全新设置已有实例时，可在完成备份位置和管理通道检查后，使用 `sudo ./fresh-install.sh "$(pwd)" <SHA256SUMS文件的SHA256> <已存在的备份父目录>`。脚本保留旧数据目录、备份旧/新包，并在失败时尝试恢复；多网络资源未能证实释放时拒绝切换。备份包含敏感身份材料，应妥善保管。实际脚本验证范围见报告。

`sudo ./uninstall.sh` 停止服务并卸载程序，仍保留设置与身份。非 systemd 系统可在解压目录运行 `sudo ./runtime/conwu run`；后台管理由该系统自己的服务工具负责。请勿同时运行同一数据目录的多个实例。

## 使用

```sh
sudo conwu status
sudo conwu web
sudo conwu network list
sudo conwu config show > settings.json
sudo conwu config apply settings.json
sudo conwu network create
sudo conwu network status <配置ID>
sudo conwu network invite <配置ID>
sudo conwu network join 123456
sudo conwu network poll <配置ID>
sudo conwu network approve <配置ID> <校验码>
```

一个网络只含主机和一个从机，同一设备可以参与多个网络。`network list` 返回本机配置 ID 与认证网络 ID；操作使用配置 ID。创建和加入会建立新的独立关系；请求同意前请核对设备及校验码。`network leave <配置ID>` 仅退出本机关系，`network close <配置ID>` 解散该双机网络，`network remove-config <配置ID>` 移除本机配置。它们不关闭设备级协调服务。

配置默认采用 FakeTCP＋HTTP。自主打洞需要 HTTPS 协调入口；无协调时应明确选择只使用已有入口。DDNS 地址不能替代配对码所需的协调服务。
`config show` 导出可编辑设置，不包含成员私钥；其中入口订阅链接可能带有用户配置的读取令牌，请勿公开。`config apply` 支持部分 JSON，不填写的设置保留；添加 `--network <配置ID>` 查看或修改单网配置，默认无参数针对设备默认模板。设备名、协调服务和 DDNS 为共享设置；修改已绑定的协调地址需要先退出该网络。

WebUI 仅监听本机 `127.0.0.1:47821`。远程管理先执行 `ssh -L 47821:127.0.0.1:47821 用户@服务器`，再在服务器执行 `sudo conwu web`，在自己的浏览器打开输出的一次性登录链接。不要将 WebUI 端口直接反向代理到公网。

## 协调与入口

在设置中开启设备级协调角色。默认监听 `http://127.0.0.1:47822`，可交给本机 Cloudflare Tunnel 提供 HTTPS。直接对外监听需配置 `https://0.0.0.0:47822` 及 PEM 证书、私钥的绝对路径。systemd 服务禁止读取用户家目录，建议证书放在 `/etc/streamlink` 并限制权限。组网成员仍需填写同一个外部 HTTPS 协调地址。

连接设置中“远端连接来源”填写对端的接收入口或 HTTPS/TXT 订阅；“本机发布来源”独立填写通向本机接收端口的公网地址/映射/订阅。入口只提供可达性，首次加入仍需配对与批准。新版入口需要响应设备同样支持入口身份探测。

协调数据位于 `/var/lib/streamlink/coordination`。从原独立协调服务迁移时，先停止旧写入者并备份数据，再迁入并启用新协调；不要同时运行两个互不同步的 Registry。本版本没有协调数据库复制或自动接管。

提供 `conwu coordinator status` 和离线 `coordinator backup|inspect|restore` 命令，以及本机协调设置中的外部 HTTPS 地址检查。备份或恢复前先关闭协调角色，备份文件请私密保管。格式、迁移步骤及验证范围见[协调服务可靠性与迁移](../../docs/aq1/协调服务可靠性与迁移-20261106.md)。

程序只回收自己登记的 TUN、子进程和防火墙规则，不改默认路由/DNS。若系统还有 firewalld 或其他独立 nft base chain，应按本机防火墙策略允许 ConWU 虚拟网段；本软件不会覆盖其他安全策略。异常退出后，下次启动根据本实例的私有记录回收遗留规则。
