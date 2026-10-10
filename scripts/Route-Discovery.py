"""Add only the dedicated metadata path to the existing HTTPS origin."""
from pathlib import Path
import subprocess
p = Path('/etc/nginx/sites-available/searxng')
original = p.read_text()
marker = '      location /streamlink-discovery/ {'
if marker not in original:
    backup = p.with_name('searxng.before-streamlink')
    if backup.exists():
        raise RuntimeError('Backup exists; inspect before retrying')
    backup.write_text(original)
    block = '''      location /streamlink-discovery/ {
          access_log off;
          client_max_body_size 8k;
          add_header Cache-Control "no-store" always;
          proxy_pass https://127.0.0.1:42860/;
          proxy_ssl_trusted_certificate /etc/streamlink-discovery/cert.pem;
          proxy_ssl_verify on;
          proxy_ssl_name ssh.space4sgsa.com;
          proxy_set_header Host ssh.space4sgsa.com;
          proxy_connect_timeout 3s;
          proxy_read_timeout 10s;
      }

'''
    if '      location /static/ {' not in original:
        raise RuntimeError('Unexpected origin config')
    p.write_text(original.replace('      location /static/ {', block + '      location /static/ {', 1))
    check = subprocess.run(['nginx', '-t'], capture_output=True, text=True)
    if check.returncode:
        p.write_text(original)
        raise RuntimeError(check.stderr)
    subprocess.run(['systemctl', 'reload', 'nginx'], check=True)
print('Dedicated discovery path configured')
