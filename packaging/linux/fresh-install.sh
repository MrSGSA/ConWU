#!/usr/bin/env bash
# Explicit fresh-install transaction for the single packaged Linux instance.
# All existing product data is retained in protected evidence and a same-filesystem quarantine.
set -Eeuo pipefail
umask 077
[[ $EUID == 0 && $# == 3 ]] || { echo '用法：sudo ./fresh-install.sh 已解包的新包目录 SHA256SUMS文件的SHA256 备份父目录' >&2; exit 2; }
for cmd in systemctl sha256sum flock tar realpath timeout python3 find grep; do command -v "$cmd" >/dev/null || { echo "缺少依赖：$cmd" >&2; exit 1; }; done
bundle=$(realpath -e -- "$1"); expected=${2,,}; parent=$(realpath -e -- "$3")
[[ $expected =~ ^[0-9a-f]{64}$ && -d $bundle && -d $parent && $parent != / ]] || { echo '参数无效' >&2; exit 1; }
[[ $bundle != /opt/streamlink/* && $bundle != /var/lib/streamlink/* && $parent != /opt/streamlink* && $parent != /var/lib/streamlink* ]] || { echo '包和备份不能位于产品安装或数据目录内' >&2; exit 1; }
[[ ! -L /opt/streamlink && ! -L /opt/streamlink/releases && ! -L /var/lib/streamlink && ! -L /etc/systemd/system/streamlink.service ]] || { echo '拒绝产品路径符号链接' >&2; exit 1; }
unit=/etc/systemd/system/streamlink.service
[[ -f $unit ]] && grep -qx '# StreamLink managed unit' "$unit" || { echo '现有服务不属于本安装器，停止操作' >&2; exit 1; }
[[ -d /var/lib/streamlink && -L /opt/streamlink/current ]] || { echo '未找到完整的现有实例' >&2; exit 1; }
old=$(readlink -f -- /opt/streamlink/current)
[[ $old == /opt/streamlink/releases/* && -d $old && ! -L $old ]] || { echo '现有版本目录不符合预期' >&2; exit 1; }
[[ -f $bundle/SHA256SUMS && ! -L $bundle/SHA256SUMS && -f $bundle/install.sh && ! -L $bundle/install.sh ]] || { echo '候选包不完整' >&2; exit 1; }
[[ $(sha256sum "$bundle/SHA256SUMS" | cut -d ' ' -f 1) == "$expected" ]] || { echo '候选清单哈希不匹配' >&2; exit 1; }
(cd -- "$bundle" && sha256sum -c SHA256SUMS >/dev/null)
exec 9>/opt/streamlink/install.lock
flock -n 9 || { echo '另一个安装或卸载任务正在运行' >&2; exit 1; }
backup=$(mktemp -d "$parent/conwu-fresh-XXXXXXXX")
chmod 0700 "$backup"
quarantine="/var/lib/streamlink.preinstall-${backup##*/}"
[[ ! -e $quarantine && ! -L $quarantine ]] || { echo '备份目标冲突' >&2; exit 1; }
active=false;enabled=false
systemctl is-active --quiet streamlink.service && active=true
systemctl is-enabled --quiet streamlink.service && enabled=true
printf '%s\n' "$old" > "$backup/previous-release.txt"
printf '%s\n' "$active" > "$backup/previous-active.txt"
printf '%s\n' "$enabled" > "$backup/previous-enabled.txt"
cp -p -- "$unit" "$backup/previous.service"
tar -C "$old" -cf "$backup/previous-package.tar" .
tar -C "$bundle" -cf "$backup/candidate-package.tar" .
# A pre-stop snapshot provides a recoverable copy even if stopping fails; the
# authoritative copy below is taken after the service has fully stopped.
tar --exclude='./control.sock' --exclude='./runtime.lock' --exclude='*.sock' -C /var/lib/streamlink -cf "$backup/data-before-stop.tar" .
stopped=false;moved=false;install_started=false
rollback(){
    local rc=$?; ((rc != 0)) || rc=1;trap - ERR INT TERM;set +e
    echo "切换失败，开始恢复；证据：$backup" >&2
    local failed=0
    if [[ $stopped == true ]]; then
        if ! systemctl stop streamlink.service; then
            echo '新服务未停止，保留原数据，不执行恢复。' >&2
            printf '%s\n' 'rollback-incomplete' > "$backup/result"
            exit "$rc"
        fi
        if [[ $moved == true ]]; then
            if [[ -e /var/lib/streamlink || -L /var/lib/streamlink ]]; then
                [[ ! -L /var/lib/streamlink ]] && mv -- /var/lib/streamlink "$backup/failed-new-data" || failed=1
            fi
            [[ ! -e /var/lib/streamlink && -d $quarantine && ! -L $quarantine ]] && mv -- "$quarantine" /var/lib/streamlink || failed=1
        fi
        if [[ $install_started == true ]]; then
            link=/opt/streamlink/.fresh-rollback-$$
            ln -s -- "$old" "$link" && mv -Tf -- "$link" /opt/streamlink/current || failed=1
            cp -p -- "$backup/previous.service" "$unit" && systemctl daemon-reload || failed=1
            if [[ $enabled == true ]]; then systemctl enable streamlink.service || failed=1; else systemctl disable streamlink.service || failed=1; fi
        fi
        if [[ $active == true ]]; then systemctl start streamlink.service || failed=1; fi
    fi
    if ((failed)); then echo '自动恢复未完全成功，请检查保留的数据、旧包和服务状态。' >&2; printf '%s\n' 'rollback-incomplete' > "$backup/result"; else printf '%s\n' 'rolled-back' > "$backup/result"; fi
    exit "$rc"
}
trap rollback ERR INT TERM
systemctl stop streamlink.service
stopped=true
systemctl is-active --quiet streamlink.service && { echo '服务未停止' >&2; false; }
tar --exclude='./control.sock' --exclude='./runtime.lock' --exclude='*.sock' -C /var/lib/streamlink -cf "$backup/data-stopped.tar" .
# Do not guess ownership from adapter names. The old multi-network service must
# expose a maintenance report; otherwise this transaction remains safely blocked.
if [[ -d /var/lib/streamlink/networks ]] && find /var/lib/streamlink/networks -mindepth 1 -maxdepth 1 -type d -print -quit | grep -q .; then
    STREAMLINK_PROFILE_ROOT=/var/lib/streamlink "$bundle/runtime/conwu" maintenance resources --json > "$backup/resources-after-stop.json"
    python3 - "$backup/resources-after-stop.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1],encoding='utf-8'))
if r.get('schemaVersion')!=1 or r.get('complete') is not True or r.get('ownedResources')!=[]:
    raise SystemExit('多网络资源未能证明全部释放；未切换数据')
PY
fi
mv -- /var/lib/streamlink "$quarantine"
moved=true
install -d -m 0700 /var/lib/streamlink
install_started=true
(trap - ERR INT TERM; cd -- "$bundle" && CONWU_INSTALL_LOCK_INHERITED=1 ./install.sh --no-start) > "$backup/install.log" 2>&1
if [[ $active == true ]]; then
    systemctl start streamlink.service
    timeout 30 bash -c 'until /usr/local/bin/conwu status >/dev/null 2>&1; do sleep 1; done'
    systemctl is-active --quiet streamlink.service
fi
printf '%s\n' 'installed' > "$backup/result"
printf '已完成全新安装。旧数据原目录：%s；受保护备份与安装日志：%s\n' "$quarantine" "$backup"
trap - ERR INT TERM
