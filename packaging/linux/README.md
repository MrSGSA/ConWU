# ConWU Linux 候选包

与 Windows 使用同一套双机多网络核心，也可兼任 HTTPS 协调设备。每个网络一主一从，通道双向；不提供串流中继。配置和入口格式见[入口与配置](../../docs/ConWU-入口与配置.md)。

本包为 Linux x86_64 / glibc 自包含包，包含 .NET 10 运行库与静态原生传输。参与网络需要 TUN、iproute2、nftables、iptables 和 root 或对应网络权限；仅提供协调不需要 TUN。Alpine/musl 和 ARM64 不适用此包。

## 安装

解压后运行 `sudo ./install.sh`，安装为 `streamlink.service`。普通更新停止原服务后替换程序，保留 `/var/lib/streamlink`；旧程序保留在 `/opt/streamlink/releases`，切换失败会尝试恢复。`--no-start` 可先安装再手动启动。

`sudo ./uninstall.sh` 卸载程序并保留设置。非 systemd 系统可运行 `sudo ./runtime/conwu run`，自行管理后台进程。兼容命令 `streamlink` 保留。

## WebUI

默认管理界面只监听本机 `127.0.0.1:47821`。运行 `sudo conwu web` 获取一次性登录链接，可通过 SSH 本地转发访问。

需要通过域名直接管理时，先从受保护的标准输入设置密码：

```sh
sudo conwu remote-admin set https://manage.example.com < /root/conwu-admin-password
sudo systemctl restart streamlink
```

密码需为 16–256 个非控制字符，文件内容不会回显。然后将 HTTPS 反向代理／Tunnel 的 `/admin/` 路径转到 `http://127.0.0.1:47823`，保留外部 Host，访问 `https://manage.example.com/admin/login`。远程管理和协调分别监听，不要把整个协调地址转到管理端口。

登录使用密码、Secure/HttpOnly Cookie、CSRF 和来源校验；协调请求不能获得管理权限。`conwu remote-admin disable` 后重启服务可关闭远程管理。未配置密码时不启动该监听。

## CLI

```sh
sudo conwu profiles
sudo conwu profile show <配置ID>
umask 077
sudo conwu profile export <配置ID> > connection.json
# 编辑连接策略、协调地址或入口来源后：
sudo conwu profile update <配置ID> connection.json --reconnect
sudo conwu network create <配置ID> "主机—笔记本"
sudo conwu network list
sudo conwu network invite <网络操作ID>
sudo conwu network join <配置ID> 123456
sudo conwu network poll <网络操作ID>
sudo conwu network approve <网络操作ID> <双方校验码>
```

`profiles` 列出配置 ID 和关联网络。`network list` 的 `id` 是本机操作用的网络 ID，`profileId` 为所引用的配置；不需要手工编辑认证网络身份。创建和加入时始终选择配置。

`profile create <名称> connection.json` 新建配置；`profile copy <ID> <名称>` 显式复制；`profile assign <配置ID> <网络操作ID> --reconnect` 更换引用；`profile delete <ID>` 只删除未关联配置。保存的设置会更新全部引用者，停止的网络在下次启动应用。

`config show`／`config apply device.json` 只管理本机设置。可以在其中的 `Coordinator` 开启协调监听。HTTP 只允许本机地址，公网通过 HTTPS／反向代理公开。协调设备不自动加入其他网络。

`network leave <网络操作ID>` 从本机退出；`network close <网络操作ID>` 由主机按授权流程解散；`start/stop/retry <网络操作ID>` 控制单条连接。协调不可用时本机退出仍可进行，不把未确认的远端撤销说成成功。

## 版本与回退

1.1 的双机目录和接收格式要求两端同步更新。已有 preview.1 的网络设置迁入配置库时分别保存，不自动合并；旧单网络权限不兼容时明确提示。更新不重置已经保存的同语义设置。

手动回退前停止服务，使用原程序和与其匹配的受保护配置备份。长期公网串流及真实 NAT 的结论由用户实测确认；本机验证不代替实际串流。
