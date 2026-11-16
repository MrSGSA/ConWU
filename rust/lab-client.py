"""Private control client, run inside the selected lab network namespace."""
import json
import sys
import time
import urllib.request
import uuid
from pathlib import Path

data = Path(sys.argv[1])
action = json.loads(sys.argv[2])
control = json.loads((data / 'panel.private.json').read_text())
origin = control['origin']
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
def request(path, body=None, session=None):
    headers = {'Origin': origin}
    if body is not None:
        headers['Content-Type'] = 'application/json'
    if session:
        headers['Cookie'] = session['cookie']
        headers['X-StreamLink-CSRF'] = session['csrf']
    with opener.open(urllib.request.Request(origin + path, None if body is None else json.dumps(body).encode(), headers), timeout=10) as response:
        raw = response.read()
        return (json.loads(raw) if raw else {}), response.headers
if action.get('method') == '_stop':
    request('/api/stop', {'secret': control['secret']})
    print('{}')
    sys.exit(0)
file = data / 'lab-session.private.json'
if file.exists():
    session = json.loads(file.read_text())
else:
    link, _ = request('/api/open', {'secret': control['secret']})
    reply, headers = request('/api/session', {'ticket': link['url'].rsplit('#', 1)[1]})
    session = {'csrf': reply['csrf'], 'cookie': headers['Set-Cookie'].split(';', 1)[0]}
    file.write_text(json.dumps(session))
if action.get('method') == '_status':
    reply, _ = request('/api/status', session=session)
else:
    action['operationId'] = str(uuid.uuid4())
    request('/api/command', action, session)
    for _ in range(300):
        reply, _ = request('/api/status?operation=' + action['operationId'], session=session)
        if reply.get('operation', {}).get('completed'):
            if reply['operation']['error']:
                raise RuntimeError(reply['operation']['error'])
            break
        time.sleep(0.1)
    else:
        raise TimeoutError('isolated command timed out')
print(json.dumps(reply))
