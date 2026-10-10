#!/bin/sh
set -eu
# Run on the explicitly selected discovery host. No existing proxy is changed.
test "$(id -u)" = 0
if ! id streamlink-discovery >/dev/null 2>&1; then useradd --system --home /var/lib/streamlink-discovery --shell /usr/sbin/nologin streamlink-discovery; fi
install -d -m 755 /opt/streamlink-discovery
install -d -m 700 -o streamlink-discovery -g streamlink-discovery /var/lib/streamlink-discovery
install -d -m 750 -o root -g streamlink-discovery /etc/streamlink-discovery
install -m 755 /tmp/StreamLink.Discovery /opt/streamlink-discovery/StreamLink.Discovery
if [ ! -f /etc/streamlink-discovery/server.pfx ]; then
  umask 077
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 -subj '/CN=ssh.space4sgsa.com' -addext 'subjectAltName=DNS:ssh.space4sgsa.com' -keyout /etc/streamlink-discovery/key.pem -out /etc/streamlink-discovery/cert.pem 2>/dev/null
  openssl pkcs12 -export -out /etc/streamlink-discovery/server.pfx -inkey /etc/streamlink-discovery/key.pem -in /etc/streamlink-discovery/cert.pem -passout pass:
  chown root:streamlink-discovery /etc/streamlink-discovery/server.pfx
  chmod 640 /etc/streamlink-discovery/server.pfx
fi
cat >/etc/systemd/system/streamlink-discovery.service <<'EOF'
[Unit]
Description=StreamLink encrypted peer discovery (no traffic relay)
After=network-online.target
Wants=network-online.target
[Service]
User=streamlink-discovery
Group=streamlink-discovery
WorkingDirectory=/opt/streamlink-discovery
ExecStart=/opt/streamlink-discovery/StreamLink.Discovery
Environment=ASPNETCORE_URLS=https://127.0.0.1:42860
Environment=ASPNETCORE_Kestrel__Certificates__Default__Path=/etc/streamlink-discovery/server.pfx
Environment=STREAMLINK_DISCOVERY_DATA=/var/lib/streamlink-discovery
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/streamlink-discovery
UMask=0077
MemoryMax=512M
TasksMax=128
LimitNOFILE=1024
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now streamlink-discovery.service
openssl x509 -in /etc/streamlink-discovery/cert.pem -outform DER | sha256sum
systemctl is-active streamlink-discovery.service
