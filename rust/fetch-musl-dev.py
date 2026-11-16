"""Fetch a pinned build dependency; pacman independently verifies its signature."""
import urllib.request
from pathlib import Path
root=Path(__file__).resolve().parent.parent/'out/verified-tools'
root.mkdir(exist_ok=True,parents=True)
opener=urllib.request.build_opener(urllib.request.ProxyHandler({'https':'http://127.0.0.1:7897'}))
for suffix in ['', '.sig']:
    name='musl-1.2.6-1-x86_64.pkg.tar.zst'+suffix
    with opener.open('https://archive.archlinux.org/packages/m/musl/'+name,timeout=30) as source:
        data=source.read(5*1024*1024+1)
        if len(data)>5*1024*1024:raise ValueError('Unexpected dependency size')
    (root/name).write_bytes(data)
    print(name,len(data),flush=True)
