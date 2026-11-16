"""Exercise the embedded UI with a private memory-adapter backend."""
import json
import os
import socket
import subprocess
import time
import urllib.request
import uuid
from pathlib import Path

root = Path(__file__).resolve().parent.parent
os.environ['TEMP'] = os.environ['TMP'] = str(root / 'out/tmp')
from playwright.sync_api import sync_playwright

data = root / 'out/lab' / ('ui-' + uuid.uuid4().hex)
executable = Path(os.environ.get('CONWU_UI_EXECUTABLE', str(root / 'out/rust-target/debug/conwu.exe'))).resolve()
build_info = json.loads(subprocess.check_output([str(executable), 'build-info'], text=True, encoding='utf-8'))
assert not build_info['labApi'], 'UI acceptance must use a deliverable build without lab commands'
process = subprocess.Popen([str(executable), 'run', '--data', str(data), '--memory', '--no-open', '--no-tray'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
control = None
errors = []
def request(path, body):
    request = urllib.request.Request(control['origin'] + path, json.dumps(body).encode(), {'Content-Type': 'application/json', 'Origin': control['origin']})
    return urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=10).read()
def port():
    with socket.socket() as connection:
        connection.bind(('0.0.0.0', 0))
        return connection.getsockname()[1]
try:
    for _ in range(200):
        if (data / 'panel.private.json').exists():
            control = json.loads((data / 'panel.private.json').read_text(encoding='utf-8'))
            break
        if process.poll() is not None:
            raise RuntimeError('isolated backend exited')
        time.sleep(0.05)
    assert control is not None and control['pid'] == process.pid
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel='msedge', headless=True)
        page = browser.new_page(viewport={'width': 1240, 'height': 800})
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.goto(control['url'])
        page.wait_for_function("() => typeof workspaceState !== 'undefined' && workspaceState?.workspaceVersion === 1")
        assert page.title().find('ConWU') >= 0
        def command(method, values, expected_error=None):
            body = {'method': method, 'operationId': str(uuid.uuid4()), **values}
            result = page.evaluate("body => api('/api/command', body)", body)
            for _ in range(200):
                result = page.evaluate("id => api('/api/status?operation='+encodeURIComponent(id))", body['operationId'])
                if result.get('operation', {}).get('completed'):
                    if expected_error is None:
                        assert not result['operation']['error'], result['operation']['error']
                    elif expected_error is True:
                        assert result['operation']['error'], 'Memory UI must not initiate an actual installation'
                    else:
                        assert result['operation']['error'] == expected_error, result['operation']['error']
                    return result
                time.sleep(0.05)
            raise TimeoutError('UI operation not completed')
        ids = []
        for name in ['Rust 网络甲', 'Rust 网络乙']:
            settings = page.evaluate('() => workspaceState.networkDefaults')
            settings.update(pathSelection='tcp-only', connectionSource='existing', discoveryMode='existing', listenPort=port(), sourcePort=port())
            settings['existingEntries'] = [{'peerSlot': 0, 'source': '198.51.100.10:' + str(settings['listenPort'])}]
            config = command('configuration', {'networkId': '', 'configuration': {'action': 'save', 'id': '', 'name': name, 'expectedRevision': 0, 'settings': settings}})
            page.evaluate('(id) => { selectedConfiguration=id; selectedNetwork=""; }', config['configurationId'])
            created = command('network', {'networkId': '', 'network': {'action': 'create-direct', 'name': name, 'configurationId': config['configurationId'], 'mode': 'tcp'}})
            ids.append(created['status']['selectedNetworkId'])
        assert ids[0] != ids[1]
        command('lab-read', {'networkId': ids[0]}, expected_error='未知后台操作')
        command('update-install', {}, expected_error=True if build_info['localInstall'] else '当前实验构建仅校验下载，不执行安装')
        page.wait_for_function('() => workspaceState.networks.length === 2')
        for navigation in ['overview', 'create', 'join', 'settings', 'coordination', 'uu', 'logs']:
            selector = page.locator('button[data-page="' + navigation + '"]').first
            if selector.count():
                selector.click()
                page.wait_for_timeout(100)
        page.wait_for_function("() => logLines.some(l => l.level === 'ERROR' && l.message.includes('update-install')) && logLines.some(l => l.level === 'INFO' && /^\\d\\d:\\d\\d:\\d\\d$/.test(l.time))")
        assert page.evaluate("() => logLines.every(l => !l.message.includes('[INFO]') && !l.message.includes('[ERROR]'))")
        page.screenshot(path=str(root / 'out/rust-ui-smoke.png'), full_page=True)
        assert not errors, errors
        browser.close()
    print(json.dumps({'embeddedUi': 'passed', 'independentNetworks': len(ids), 'javascriptErrors': len(errors),
                      'labApiEnabled': False, 'localInstallEnabled': build_info['localInstall'], 'production': build_info['production'], 'executable': str(executable)}, ensure_ascii=False))
finally:
    if control is not None:
        try:
            request('/api/stop', {'secret': control['secret']})
        except Exception:
            pass
    try:
        process.wait(timeout=20)
    except subprocess.TimeoutExpired:
        process.terminate()
        process.wait(timeout=5)
