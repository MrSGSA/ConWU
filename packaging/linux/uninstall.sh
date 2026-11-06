#!/usr/bin/env bash
set -euo pipefail
[[ $EUID == 0 ]] || { echo '请使用 sudo ./uninstall.sh'; exit 1; }
unit=/etc/systemd/system/streamlink.service
[[ -f $unit && ! -L $unit ]] && grep -q '^# StreamLink managed unit$' "$unit" || { echo '未找到本安装器创建的 ConWU / StreamLink 服务'; exit 1; }
[[ -d /opt/streamlink && ! -L /opt/streamlink && $(realpath /opt/streamlink) == /opt/streamlink ]] || { echo '安装目录不符合预期，已停止卸载'; exit 1; }
exec 9>/opt/streamlink/install.lock
flock -n 9 || { echo '另一个安装或卸载任务正在运行'; exit 1; }
systemctl stop streamlink.service
systemctl disable streamlink.service
rm -- "$unit"
if [[ $(readlink /usr/local/bin/streamlink || true) == /opt/streamlink/current/streamlink ]]; then rm -- /usr/local/bin/streamlink;fi
if [[ $(readlink /usr/local/bin/conwu || true) == /opt/streamlink/current/streamlink ]]; then rm -- /usr/local/bin/conwu;fi
systemctl daemon-reload
rm -rf -- /opt/streamlink
echo 'ConWU 程序已卸载。/var/lib/streamlink 中的设置、成员身份和协调数据已保留。'
