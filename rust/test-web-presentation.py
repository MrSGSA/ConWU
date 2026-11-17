"""Exercise the real WebUI with an isolated memory backend (requires Playwright)."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import urllib.request
import uuid

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--app', type=Path, default=ROOT / 'out/rust-target/release/conwu.exe')
parser.add_argument('--source-assets', action='store_true', help='Test edited assets before rebuilding')
args = parser.parse_args()
data = ROOT / 'out' / ('web-presentation-' + uuid.uuid4().hex)
process = subprocess.Popen([str(args.app.resolve()), 'run', '--data', str(data), '--memory',
    '--no-open', '--no-tray'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
control = None
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def request(path, body):
    req = urllib.request.Request(control['origin'] + path, json.dumps(body).encode(),
        {'Content-Type': 'application/json', 'Origin': control['origin']})
    with opener.open(req, timeout=15) as response:
        raw = response.read()
        return json.loads(raw) if raw else None


def command(body, expect_error=False):
    body = dict(body, operationId=uuid.uuid4().hex)
    result = request('/api/local', dict(secret=control['secret'], command=body))
    deadline = time.monotonic() + 20
    while result.get('operation') and not result['operation']['completed']:
        assert time.monotonic() < deadline, 'Isolated operation timed out'
        time.sleep(.05)
        result = request('/api/local', dict(secret=control['secret'],
            command=dict(method='status', operationId=body['operationId'])))
    error = result.get('error') or result.get('operation', {}).get('error')
    assert bool(error) == expect_error, error or 'Expected an isolated diagnostic error'
    return result


def tick(page, count=2):
    start = page.evaluate('lastStatusAt')
    page.wait_for_function('(start) => lastStatusAt >= start + 1900', arg=start, timeout=10000)
    if count > 1:
        tick(page, count - 1)


def select_text(page, selector):
    return page.evaluate('''selector => {
        const node=document.querySelector(selector),range=document.createRange();
        range.selectNodeContents(node);
        window.getSelection().removeAllRanges();window.getSelection().addRange(range);
        window.__selectedNode=node;return window.getSelection().toString();
    }''', selector)


def retained(page, text):
    assert page.evaluate('window.getSelection().toString()') == text
    assert page.evaluate('window.__selectedNode.isConnected')


def clear_selection(page):
    page.evaluate('window.getSelection().removeAllRanges()')


try:
    for _ in range(300):
        file = data / 'panel.private.json'
        if file.exists():
            control = json.loads(file.read_text(encoding='utf-8'))
            break
        assert process.poll() is None, 'Isolated backend exited'
        time.sleep(.05)
    assert control and control['pid'] == process.pid
    url = request('/api/open', {'secret': control['secret']})['url']
    errors = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel='msedge', headless=True)
        page = browser.new_page(viewport={'width': 1240, 'height': 850})
        page.set_default_timeout(10000)
        page.on('pageerror', lambda error: errors.append(str(error)))
        if args.source_assets:
            assets = ROOT / 'src/ConWU.Web/wwwroot'
            def edited(route):
                name = route.request.url.split('?')[0].removeprefix(control['origin']).strip('/') or 'index.html'
                response = route.fetch()
                route.fulfill(response=response, body=(assets / name).read_bytes())
            for path in ('/', '/app.js', '/experience.js'):
                page.route(control['origin'] + path, edited)
        page.goto(url)
        page.wait_for_function('() => workspaceState?.workspaceVersion === 1')

        text = select_text(page, '#page-title')
        page.evaluate("unavailable('隔离测试：后台暂时不可用')")
        retained(page, text)
        clear_selection(page)
        page.wait_for_function("() => document.getElementById('notice').textContent.includes('隔离测试：后台暂时不可用')")
        text = select_text(page, '#page-title')
        tick(page)
        retained(page, text)
        print('overview selection passed', flush=True)
        clear_selection(page)
        page.wait_for_function('() => !window.__selectedNode.isConnected')

        page.locator('button[data-page="logs"]').first.click()
        command(dict(method='selection-regression-first'), expect_error=True)
        page.wait_for_function("() => document.getElementById('terminal-lines').textContent.includes('selection-regression-first')")
        # Actual mouse drag remains protected even while it spans a poll.
        line = page.locator('#terminal-lines .message').first
        line.scroll_into_view_if_needed()
        box = line.bounding_box()
        page.mouse.move(box['x'] + 2, box['y'] + box['height']/2)
        page.mouse.down()
        page.mouse.move(box['x'] + min(180, box['width'] - 3), box['y'] + box['height']/2, steps=12)
        dragged = page.evaluate('window.getSelection().toString()')
        assert dragged
        tick(page, 1)
        assert page.evaluate('window.getSelection().toString()') == dragged
        page.mouse.up()
        clear_selection(page)
        print('mouse selection passed', flush=True)

        text = page.evaluate('''() => {
            const box=document.getElementById('terminal-lines'),range=document.createRange();
            range.setStart(box.firstElementChild.firstElementChild.firstChild,0);
            const last=box.lastElementChild.lastElementChild.firstChild;
            range.setEnd(last,last.length);
            window.getSelection().removeAllRanges();window.getSelection().addRange(range);
            window.__selectedNode=box;return window.getSelection().toString();
        }''')
        command(dict(method='selection-regression-second'), expect_error=True)
        tick(page)
        retained(page, text)
        assert not page.locator('#terminal-lines').inner_text().endswith('selection-regression-second')
        clear_selection(page)
        page.wait_for_function("() => document.getElementById('terminal-lines').textContent.includes('selection-regression-second')")
        print('multiline selection and catch-up passed', flush=True)
        search = page.locator('#log-search')
        search.fill('selection-regression')
        search.evaluate('(input) => {input.setSelectionRange(2,10);window.__selectedInput=input;}')
        tick(page)
        assert page.evaluate('window.__selectedInput.isConnected && window.__selectedInput.selectionStart===2 && window.__selectedInput.selectionEnd===10')
        search.press('ArrowRight')
        clear_selection(page)
        page.locator('button[data-page="create"]').first.click()

        page.locator('button[data-ui-action="open-editor"][data-network=""]').click()
        page.locator('input[name="mode"][value="existing"]').check()
        page.locator('button[data-ui-section="entry"]').click()
        assert '当前协议使用 IPv4' in page.locator('#settings-fields').inner_text()
        page.locator('button[data-ui-section="network"]').click()
        page.locator('input[name="protocol"][value="tcp"]').check()
        page.locator('input[name="mode"][value="existing"]').check()
        page.locator('button[data-ui-section="entry"]').click()
        assert '支持 IPv4／IPv6' in page.locator('#settings-fields').inner_text()
        hint = select_text(page, '.entry-copy')
        tick(page)
        retained(page, hint)
        clear_selection(page)
        with socket.socket() as port_probe:
            port_probe.bind(('127.0.0.1', 0))
            port = port_probe.getsockname()[1]
        # Reserved documentation addresses exercise generation only; nothing is
        # sent to them. Loopback is intentionally forbidden in shareable codes.
        page.locator('input[data-entry-index="0"]').fill('tcp://192.0.2.23:' + str(port))
        page.locator('button[data-action="add-entry"]').click()
        page.locator('input[data-entry-index="1"]').fill('tcp://[2001:db8::23]:' + str(port))
        page.locator('button[data-ui-section="port"]').click()
        page.locator('input[data-key="listen"]').fill(str(port))
        page.locator('button[data-ui-action="save-editor"]').click()
        page.wait_for_function("() => !document.getElementById('network-dialog').open || document.getElementById('settings-error')?.textContent")
        assert not page.locator('#network-dialog').evaluate('(dialog) => dialog.open'), page.locator('#settings-error').inner_text()
        page.locator('#new-network-name').fill('界面隔离验收')
        page.locator('#create-network').click()
        page.wait_for_function("() => document.getElementById('invitation-dialog').open")
        assert page.locator('#invitation-family-field').is_visible()
        assert page.locator('#invitation-family').input_value() == ''
        page.locator('#invitation-generate').click()
        page.wait_for_function("() => document.getElementById('invitation-code-length').textContent==='IPv4 · 16 位'")
        page.locator('#invitation-family').select_option('ipv6')
        page.locator('#invitation-generate').click()
        page.wait_for_function("() => document.getElementById('invitation-code-length').textContent==='IPv6 · 36 位'")
        assert len(page.locator('#invitation-code').get_attribute('data-code')) == 36
        assert not errors, errors
        result = dict(version=page.evaluate('workspaceState.version'), overviewSelection=True,
            mouseDragAcrossRefresh=True, multilineLogSelection=True, pendingLogsCatchUp=True,
            inputSelection=True, dialogSelection=True, ipv4Default16=True, explicitIpv6Code36=True,
            javascriptErrors=errors, isolatedMemoryBackend=True, embeddedAssets=not args.source_assets)
        print(json.dumps(result, ensure_ascii=True), flush=True)
        (data / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        browser.close()
finally:
    if control:
        try: request('/api/stop', {'secret': control['secret']})
        except Exception: pass
    try: process.wait(timeout=20)
    except subprocess.TimeoutExpired:
        process.terminate()
        process.wait(timeout=5)
