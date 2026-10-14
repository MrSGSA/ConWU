#!/bin/sh
set -eu
# Prepared, isolated deployment. Explicit invocation is required.
test "$(id -u)" = 0
source_dir=${1:?Provide the extracted complete coordination-linux-x64 directory}
case "$source_dir" in /*) ;; *) echo 'Absolute input path required' >&2; exit 1;; esac
test -f "$source_dir/StreamLink.Discovery"
test -f "$source_dir/deployment.json"
test ! -e /etc/systemd/system/streamlink-personal-v3.service
test ! -e /opt/streamlink-personal-v3
if ! id streamlink-personal-v3 >/dev/null 2>&1; then useradd --system --home /var/lib/streamlink-personal-v3 --shell /usr/sbin/nologin streamlink-personal-v3; fi
install -d -m 755 /opt/streamlink-personal-v3
cp -R -- "$source_dir/." /opt/streamlink-personal-v3/
chmod 755 /opt/streamlink-personal-v3/StreamLink.Discovery
install -d -m 700 -o streamlink-personal-v3 -g streamlink-personal-v3 /var/lib/streamlink-personal-v3
cat > /etc/systemd/system/streamlink-personal-v3.service <<'UNIT'
[Unit]
Description=StreamLink personal v3 metadata coordination (no business relay)
After=network-online.target
Wants=network-online.target
[Service]
User=streamlink-personal-v3
Group=streamlink-personal-v3
WorkingDirectory=/opt/streamlink-personal-v3
ExecStart=/opt/streamlink-personal-v3/StreamLink.Discovery
Environment=ASPNETCORE_URLS=http://127.0.0.1:42863
Environment=STREAMLINK_DISCOVERY_DATA=/var/lib/streamlink-personal-v3
Environment=STREAMLINK_TRUST_CLOUDFLARE=1
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/streamlink-personal-v3
UMask=0077
MemoryMax=512M
TasksMax=128
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now streamlink-personal-v3.service
echo 'Isolated service started on HTTP 127.0.0.1:42863; no original service/tunnel/STUN changed.'
