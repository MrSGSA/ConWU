#!/bin/sh
set -eu
# Dedicated StreamLink backend. Existing discovery/searxng/tunnel services are untouched.
test "$(id -u)" = 0
binary=${1:?Pass the uploaded StreamLink.Discovery executable}
test -f "$binary"
if ! id streamlink-coordination >/dev/null 2>&1; then
  useradd --system --home /var/lib/streamlink-coordination --shell /usr/sbin/nologin streamlink-coordination
fi
install -d -m 755 /opt/streamlink-coordination
install -d -m 700 -o streamlink-coordination -g streamlink-coordination /var/lib/streamlink-coordination
version="0.4.0-$(date +%Y%m%d%H%M%S)"
install -d -m 755 "/opt/streamlink-coordination/$version"
install -m 755 "$binary" "/opt/streamlink-coordination/$version/StreamLink.Discovery"
cat > /etc/systemd/system/streamlink-coordination.service <<EOF
[Unit]
Description=StreamLink independent coordination (metadata only, no traffic relay)
After=network-online.target
Wants=network-online.target
[Service]
User=streamlink-coordination
Group=streamlink-coordination
WorkingDirectory=/opt/streamlink-coordination/$version
ExecStart=/opt/streamlink-coordination/$version/StreamLink.Discovery
Environment=ASPNETCORE_URLS=http://127.0.0.1:42861
Environment=STREAMLINK_DISCOVERY_DATA=/var/lib/streamlink-coordination
Environment=STREAMLINK_TRUST_CLOUDFLARE=1
Environment=DOTNET_BUNDLE_EXTRACT_BASE_DIR=/var/lib/streamlink-coordination/bundle
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/streamlink-coordination
UMask=0077
MemoryMax=512M
TasksMax=128
LimitNOFILE=1024
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable streamlink-coordination.service
systemctl restart streamlink-coordination.service
sleep 2
systemctl is-active streamlink-coordination.service
curl --fail --silent http://127.0.0.1:42861/health
