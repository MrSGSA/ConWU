"""Build an offline, self-contained preview without touching the live web assets."""

from pathlib import Path
import json
import re


root = Path(__file__).resolve().parent.parent
base = root / 'previews/ConWU-界面预览-20261108-v2.html'
source = root / 'scripts/preview'
output = root / 'previews/ConWU-正式版界面预览-20261110-v5.html'

# Keep the established layout, Tokyo Night palette and rotated ConWU mark.
html = base.read_text(encoding='utf-8').split('<script>', 1)[0]
html = html.replace('</style>', (source / 'release-20261110.css').read_text(encoding='utf-8') + '\n</style>', 1)
html = re.sub(r'\s*<div class="nav-label">.*?</div>', '', html, count=1)
html = re.sub(r'\s*<button class="nav" data-page="coordinator".*?</button>', '', html, count=1)
html = re.sub(r'\s*<header class="topbar">.*?</header>', '', html, count=1)
html = re.sub(
    r' <div class="sidebar-bottom">.*?</aside>',
    ''' <div class="sidebar-bottom">
  <div class="sidebar-tools"><div class="backend" role="status"><span class="dot good"></span><span>后台运行中</span></div><button class="btn icon-only" data-action="theme" id="theme-button" aria-label="切换浅色外观" title="切换浅色外观"><svg class="icon"><use href="#i-sun"/></svg></button></div>
  <div class="sidebar-device row"><div class="avatar" id="sidebar-avatar">AL</div><div class="grow"><div class="small" id="sidebar-name">Akane-Laptop</div><div class="small dim">本机设备</div></div></div>
 </div>
</aside>''',
    html, count=1, flags=re.S,
)
html = re.sub(r'<dialog class="small-dialog" id="lookup-dialog".*?</dialog>\n', '', html, count=1, flags=re.S)
html = html.replace(
    '<div class="toast" id="toast"',
    '''<dialog class="small-dialog help-dialog" id="help-dialog" aria-labelledby="help-title"><div class="modal-header"><h2 id="help-title"></h2><button class="btn icon-only" data-close="help-dialog" aria-label="关闭帮助"><svg class="icon"><use href="#i-x"/></svg></button></div><div class="pad" id="help-content"></div><div class="dialog-actions"><button class="btn primary" data-close="help-dialog">知道了</button></div></dialog>
<div class="toast" id="toast"''', 1,
)

tcp = [
    'fwa.lifesizecloud.com:3478', 'stun.nextcloud.com:3478',
    'stun.sipnet.com:3478', 'global.turn.twilio.com:3478',
]
tcp.extend(
    v.strip() for v in (root / 'src/StreamLink.Core/tcp-stun-snapshot.txt').read_text(encoding='utf-8').splitlines()
    if v.strip() and not v.lstrip().startswith('#')
)
seen = set()
tcp = [v for v in tcp if not (v.lower() in seen or seen.add(v.lower()))]
udp = ['stun.miwifi.com:3478', 'stun.chat.bilibili.com:3478', 'stun.hitv.com:3478', 'stun.nextcloud.com:3478']
script = (source / 'release-20261110.js').read_text(encoding='utf-8')
script = script.replace('__STUN_DEFAULTS__', json.dumps({'tcp': tcp, 'udp': udp}, ensure_ascii=False))
html += '<script>\n' + script + '\n</script>\n</body></html>\n'
assert '<header class="topbar">' not in html
assert 'data-page="coordinator"' not in html
assert '__STUN_DEFAULTS__' not in html
assert '<script src=' not in html and '<link rel="stylesheet"' not in html
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(html, encoding='utf-8')
print(f'{output}\nTCP STUN: {len(tcp)}; UDP STUN: {len(udp)}; {output.stat().st_size} bytes')
