# StreamLink Linux 候选包

同一程序可以参与组网、提供 HTTPS 协调服务，或同时承担两项功能。默认 FakeTCP＋HTTP，不自动改走 UDP。协调服务默认关闭，不会自动开放公网端口。

本包为 x86_64 / glibc 自包含包，内含 .NET 10 运行库与静态链接原生传输。已在 Arch Linux / WSL 的隔离网络命名空间验证；其他发行版、真实 NAT、Windows/Linux 混合实机及长时间大码率串流需继续验证，不能把本包视为这些项目已经通过。Alpine/musl、ARM64 不适用此包。

参与网络需要 Linux TUN、iproute2、nftables、iptables（可使用 nft 后端）以及 root 或相应的网络管理权限。仅提供协调服务不需要这些网络组件。WebUI 不依赖 Linux 图形环境。

## 安装和更新

解压后执行 `sudo ./install.sh`，安装为 `streamlink.service` 并启动。`--no-start` 只安装，不立即运行。旧服务先停止，再切换程序；更新保持原开机启动选择，保留 `/var/lib/streamlink` 的设置与成员、协调数据。原程序保留在 `/opt/streamlink/releases` 供回退；启动失败会尝试恢复原版本。

`sudo ./uninstall.sh` 停止服务并卸载程序，仍保留设置与身份。非 systemd 系统可在解压目录运行 `sudo ./runtime/streamlink run`；后台管理由该系统自己的服务工具负责。请勿同时运行同一数据目录的多个实例。

## 使用

```sh
sudo streamlink status
sudo streamlink web
sudo streamlink config show > settings.json
sudo streamlink config apply settings.json
sudo streamlink network create
sudo streamlink network invite
sudo streamlink network join 123456
sudo streamlink network poll
sudo streamlink network approve 123456
```

配对双方运行 `network poll` 查看设备名及校验码，一致后由已获准成员批准。CLI 以 JSON 返回进度、状态和错误。`network leave 网络ID` 退出本机，`network close 网络ID` 解散整个网络；ID 必须与当前网络完全一致。它们不改写用户保存的设置，也不关闭本机协调服务。

`config show` 导出可编辑设置，不包含成员私钥；其中入口订阅链接可能带有用户配置的读取令牌，请勿公开。`config apply` 支持部分 JSON，不填写的设置保留；修改网络绑定的协调地址需要先退出该网络。

WebUI 仅监听本机 `127.0.0.1:47821`。远程管理先执行 `ssh -L 47821:127.0.0.1:47821 用户@服务器`，再在服务器执行 `sudo streamlink web`，在自己的浏览器打开输出的一次性登录链接。不要将 WebUI 端口直接反向代理到公网。

## 协调与入口

在“本机协调服务”开启协调角色。默认监听 `http://127.0.0.1:47822`，可交给本机 Cloudflare Tunnel 提供 HTTPS。直接对外监听需配置 `https://0.0.0.0:47822` 及 PEM 证书、私钥的绝对路径。systemd 服务禁止读取用户家目录，建议证书放在 `/etc/streamlink` 并限制权限。组网成员仍需填写同一个外部 HTTPS 协调地址。

“网络入口”填写已有网络内任一成员的接收入口或 HTTPS/TXT 订阅；“提供网络入口”独立填写通向本机接收端口的公网地址/映射/订阅。入口只提供可达性，首次加入仍需配对与批准。旧版入口的绑定关系和设置保留；新版入口需要响应设备同样支持入口身份探测。

协调数据位于 `/var/lib/streamlink/coordination`。从原独立协调服务迁移时，先备份、停止旧写入者，再完整复制它的数据目录到此处并保持 root 私有权限，最后启用新协调；不要同时运行两个互不同步的 Registry。本版本没有协调数据库复制或自动接管。

程序只回收自己登记的 TUN、子进程和防火墙规则，不改默认路由/DNS。若系统还有 firewalld 或其他独立 nft base chain，应按本机防火墙策略允许 StreamLink 虚拟网段；本软件不会覆盖其他安全策略。异常退出后，下次启动根据本实例的私有记录回收遗留规则。
