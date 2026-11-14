#!/usr/bin/env bash
set -euo pipefail
[[ $EUID == 0 ]] || { echo '请使用 sudo ./install.sh'; exit 1; }
[[ ${1:-} == '' || ${1:-} == '--no-start' ]] || { echo '用法：install.sh [--no-start]'; exit 1; }
for cmd in systemctl sha256sum flock; do command -v "$cmd" >/dev/null || { echo "缺少安装依赖：$cmd"; exit 1; }; done
[[ -d /run/systemd/system ]] || { echo '此安装方式需要 systemd；非 systemd 系统可直接运行 runtime/conwu run。'; exit 1; }
[[ -c /dev/net/tun ]] || echo '系统未提供 TUN，仍可提供协调；参与网络前请启用 /dev/net/tun。'
for cmd in ip nft iptables; do command -v "$cmd" >/dev/null || echo "缺少 $cmd，仍可提供协调；参与网络前请补齐网络工具。"; done
source_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
cd -- "$source_dir"
sha256sum -c SHA256SUMS >/dev/null
[[ $(uname -m) == x86_64 ]] || { echo '此包只适用于 Linux x86_64。'; exit 1; }
./runtime/conwu help >/dev/null
./runtime/components/udp2raw-native --native-info >/dev/null
./runtime/components/conwu-phantun --conwu-info >/dev/null
./runtime/components/conwu-raw --conwu-info >/dev/null
for path in /opt/streamlink /opt/streamlink/releases /var/lib/streamlink; do
    [[ ! -L $path ]] || { echo "拒绝通过符号链接安装：$path"; exit 1; }
done
install -d -m 0755 /opt/streamlink /opt/streamlink/releases
if [[ ${CONWU_INSTALL_LOCK_INHERITED:-} == 1 ]]; then
    [[ $(readlink /proc/$$/fd/9 2>/dev/null) == /opt/streamlink/install.lock ]] || { echo '安装锁继承无效'; exit 1; }
else
    exec 9>/opt/streamlink/install.lock
    flock -n 9 || { echo '另一个安装或卸载任务正在运行'; exit 1; }
fi
unit=/etc/systemd/system/streamlink.service
if [[ -e $unit ]] && ! (sed 's/\r$//' "$unit" | grep -qx '# StreamLink managed unit'); then echo '已有同名服务不是本安装器创建，请先核对。'; exit 1; fi
if [[ -e /usr/local/bin/streamlink || -L /usr/local/bin/streamlink ]]; then
    [[ $(readlink /usr/local/bin/streamlink) == /opt/streamlink/current/streamlink ]] || { echo '/usr/local/bin/streamlink 已被其他程序占用'; exit 1; }
fi
if [[ -e /usr/local/bin/conwu || -L /usr/local/bin/conwu ]]; then
    [[ $(readlink /usr/local/bin/conwu) == /opt/streamlink/current/streamlink ]] || { echo '/usr/local/bin/conwu 已被其他程序占用'; exit 1; }
fi
install -d -m 0700 /var/lib/streamlink
build=$(sha256sum SHA256SUMS | cut -c1-16)
release=/opt/streamlink/releases/$build
stage=$(mktemp -d /opt/streamlink/releases/.install-XXXXXXXX)
trap '[[ -z ${stage:-} ]] || rm -rf -- "$stage"' EXIT
cp -a -- runtime/. "$stage/"
chown -R root:root "$stage"
chmod 0755 "$stage/conwu" "$stage/streamlink" "$stage/components/udp2raw-native" "$stage/components/conwu-phantun" "$stage/components/conwu-raw"
if [[ ! -d $release ]]; then mv -- "$stage" "$release"; stage=''; fi
old=$(readlink /opt/streamlink/current || true)
was_active=false;systemctl is-active --quiet streamlink.service && was_active=true
first=true;[[ -e $unit ]] && first=false
backup=$(mktemp /opt/streamlink/.unit-XXXXXXXX)
[[ ! -e $unit ]] || cp -p -- "$unit" "$backup"
systemctl stop streamlink.service 2>/dev/null || { [[ $first == true ]] || exit 1; }
link=/opt/streamlink/.current-$$
ln -s -- "$release" "$link";mv -Tf -- "$link" /opt/streamlink/current
ln -sfn -- /opt/streamlink/current/streamlink /usr/local/bin/streamlink
# Both commands follow the same atomic current link, including rollback to a
# pre-rename release. Keep the service/data identity to inherit saved settings.
ln -sfn -- /opt/streamlink/current/streamlink /usr/local/bin/conwu
install -m 0644 conwu.service "$unit"
systemctl daemon-reload
if [[ $first == true ]]; then systemctl enable streamlink.service; fi
if [[ ${1:-} != '--no-start' && ( $was_active == true || $first == true ) ]]; then
    if ! systemctl start streamlink.service || ! timeout 15 sh -c 'until /usr/local/bin/streamlink status >/dev/null 2>&1; do sleep 1; done'; then
        echo '新版启动失败，正在恢复原程序和服务定义；用户设置未清空。'
        systemctl stop streamlink.service || true
        if [[ -n $old ]]; then ln -s -- "$old" "$link";mv -Tf -- "$link" /opt/streamlink/current;fi
        if [[ -s $backup ]]; then cp -p -- "$backup" "$unit";systemctl daemon-reload;fi
        if [[ $was_active == true ]]; then systemctl start streamlink.service;fi
        rm -f -- "$backup";exit 1
    fi
fi
rm -f -- "$backup"
echo '已安装。原有设置、成员身份及协调数据均保留在 /var/lib/streamlink。'
echo '查看状态：sudo conwu status；打开面板：sudo conwu web'
echo '卸载程序请运行包内 sudo ./uninstall.sh；卸载同样保留设置。'
