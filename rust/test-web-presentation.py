"""Exercise the real WebUI with an isolated memory backend (requires Playwright)."""
import argparse
import copy
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
            for path in ('/', '/app.js', '/workspace.js', '/uu-takeover.js', '/experience.js'):
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
        ipv4_code = page.locator('#invitation-code').get_attribute('data-code')
        page.locator('#invitation-family').select_option('ipv6')
        page.locator('#invitation-generate').click()
        page.wait_for_function("() => document.getElementById('invitation-code-length').textContent==='IPv6 · 36 位'")
        assert len(page.locator('#invitation-code').get_attribute('data-code')) == 36

        # Controlled status events exercise presentation only. Membership and
        # authentication are covered by the backend's real pairing tests.
        page.locator('button[data-ui-action="close-invitation"]').click()
        page.locator('button[data-page="overview"]').first.click()
        original_status = page.evaluate('JSON.parse(JSON.stringify(workspaceState))')
        incoming = copy.deepcopy(original_status)
        incoming['networks'][0]['status']['pairing'] = dict(active=True, owner=True,
            candidate='a'*32, peerName='选区保留申请', verification='123456',
            proposedIp='10.203.1.2', expires=int(time.time())+120, direct=True)
        feed = {'status': incoming}
        def injected_status(route):
            response = route.fetch()
            body = response.json()
            if feed['status'] is not None:
                body['status'] = feed['status']
            route.fulfill(response=response, json=body)
        page.route(control['origin']+'/api/status**', injected_status)
        text = select_text(page, '#page-title')
        tick(page, 1)
        retained(page, text)
        assert page.locator('#requests-count').is_visible()
        assert page.locator('#requests-count').inner_text() == '1'
        page.locator('button[data-page="requests"]').first.click()
        assert '选区保留申请' in page.locator('#content').inner_text()
        clear_selection(page)
        feed['status'] = None
        tick(page, 1)
        print('new request badge updates during selection passed', flush=True)

        decisions = []
        def presentation_mutation(route):
            body = route.request.post_data_json
            action = body.get('network', {}).get('action')
            if body.get('method') == 'network' and action in ('approve', 'reject'):
                pair = feed['status']['networks'][0]['status']['pairing']
                assert body['network']['candidate'] == pair['candidate']
                pair.update(pending=False, approved=action == 'approve',
                    active=action == 'approve', outcome='' if action == 'approve' else 'Rejected',
                    phase='Delivering' if action == 'approve' else 'Rejected')
                decisions.append(action)
            elif body.get('method') == 'network' and action in ('leave', 'remove-network'):
                rows = feed['status']['networks']
                target = next(n for n in rows if n['id'] == body['networkId'])
                assert not target['status']['networkId']
                assert bool(target['status'].get('networkRevoked')) == (action == 'remove-network')
                feed['status']['networks'] = [n for n in rows if n['id'] != target['id']]
                decisions.append('remove-revoked' if action == 'remove-network' else 'remove-request')
            elif body.get('method') == 'update-dismiss':
                result = feed['status']['localUpdate']
                assert body['localUpdate']['receiptId'] == result['receiptId']
                result['acknowledged'] = True
                decisions.append('dismiss-update')
            else:
                route.continue_()
                return
            route.fulfill(json=dict(ok=True, api=1, status=feed['status'],
                operation=dict(id=body['operationId'], completed=True, phase='', error='')))
        page.route(control['origin']+'/api/command', presentation_mutation)
        for decision in ('approve', 'reject'):
            feed['status'] = copy.deepcopy(incoming)
            feed['status']['networks'][0]['status']['pairing']['pending'] = True
            tick(page, 1)
            page.locator('[data-ui-action="'+decision+'"]').click()
            page.wait_for_function("() => document.getElementById('content').textContent.includes('暂无加入申请')")
            assert page.locator('#requests-count').is_hidden()
        assert decisions == ['approve', 'reject']
        print('approval and rejection remove cards and badges passed', flush=True)

        uu = copy.deepcopy(original_status)
        for number in (1, 2):
            placeholder = copy.deepcopy(uu['networks'][0])
            placeholder.update(id=uuid.uuid4().hex, name='连接 '+str(number))
            placeholder['status'].update(networkId='', isOwner=False, networkCreatedHere=False)
            uu['networks'].append(placeholder)
        uu['uuTakeover'] = dict(supported=True, settings=dict(enabled=True),
            state='Active', rulesActive=True, trafficObserved=False, networks=[])
        feed['status'] = uu
        tick(page, 1)
        page.locator('button[data-page="uu"]').first.click()
        assert '不支持' not in page.locator('#uu-takeover-state').inner_text()
        assert page.locator('[data-uu-network]').count() == 1
        assert '连接 1' not in page.locator('#uu-takeover-networks').inner_text()
        uu['uuTakeover'].update(state='Ready')
        tick(page, 1)
        assert '等待实际流量' in page.locator('#uu-takeover-state').inner_text()
        assert 'good' not in page.locator('#uu-takeover-dot').get_attribute('class')
        uu['uuTakeover'].update(state='Transmitting', trafficObserved=True)
        tick(page, 1)
        assert 'good' in page.locator('#uu-takeover-dot').get_attribute('class')
        print('UU legacy state, approved networks and traffic confirmation passed', flush=True)

        updated = copy.deepcopy(original_status)
        updated['localUpdate'] = dict(supported=True, state='Installed', busy=False,
            version='1.5.0', message='更新已完成', receiptId='a'*64, acknowledged=False)
        feed['status'] = updated
        page.evaluate("localStorage.setItem('conwu-local-update',String(Date.now()));notice('正在本机安装',false,'update')")
        tick(page, 1)
        assert page.evaluate("localStorage.getItem('conwu-local-update')") is None
        assert page.locator('#notice').is_hidden()
        page.locator('button[data-page="settings"]').first.click()
        assert '更新已完成' in page.locator('#local-update-state').inner_text()
        page.locator('[data-ui-action="dismiss-update"]').click()
        page.wait_for_function("() => !document.getElementById('local-update-state')")
        updated['localUpdate'].update(receiptId='b'*64, acknowledged=False)
        tick(page, 1)
        page.wait_for_function("() => !document.getElementById('local-update-state')", timeout=20000)
        assert decisions.count('dismiss-update') == 2
        print('update receipt dismissal, automatic expiry and installation notice cleanup passed', flush=True)

        pending = copy.deepcopy(original_status)
        guest = pending['networks'][0]
        guest['status'].update(networkId='', isOwner=False, networkCreatedHere=False)
        guest['status']['pairing'] = dict(active=True, owner=False, expires=int(time.time())+120,
            verification='', state='正在启用本机承载组件')
        pending['selectedNetworkId'] = guest['id']
        def injected_join(route):
            body = route.request.post_data_json
            if body.get('method') == 'network' and body.get('network',{}).get('action') == 'join-compact':
                feed['status'] = pending
                route.fulfill(json=dict(ok=True, api=1, status=pending,
                    operation=dict(id=body['operationId'], completed=True, phase='', error='')))
            else:
                route.continue_()
        page.route(control['origin']+'/api/command', injected_join)
        page.locator('button[data-page="join"]').first.click()
        page.locator('#join-invite').fill(ipv4_code)
        page.locator('#join-submit').click()
        page.wait_for_function("() => document.querySelector('#join-card h2')?.textContent==='正在联系主机'")
        # The membership may already be committed while the guest retries the
        # delivery acknowledgement. Show the joined state as soon as it exists.
        guest['status'].update(networkId=uuid.uuid4().hex, directPeers=1)
        tick(page, 1)
        assert page.locator('#join-card h2').inner_text() == '已加入 ' + guest['name']
        guest['status'].update(networkId='', directPeers=0)
        message = '本机 Mimic XDP 队列检查失败（隔离测试）'
        guest['status']['pairing'].update(active=False, error=message, state=message)
        tick(page, 1)
        assert page.locator('#join-error').inner_text() == message
        assert page.locator('#join-submit').is_visible()
        assert page.locator('#join-invite').input_value().replace('-', '') == ipv4_code
        page.unroute(control['origin']+'/api/command', injected_join)
        page.locator('#unapproved-requests [data-ui-action="remove-network"]').click()
        assert '移除加入申请' in page.locator('#dialog-title').inner_text()
        page.locator('#dialog-confirm').click()
        page.wait_for_function("() => !document.getElementById('unapproved-requests')")
        assert decisions.count('remove-request') == 1

        guest['status'].update(networkRevoked=True, state='主机已撤回本机授权', pairing=None)
        pending['networks'] = [guest]
        tick(page, 1)
        assert page.locator('#revoked-networks').get_by_text('主机已撤回本机授权').is_visible()
        assert page.locator('#unapproved-requests').count() == 0
        page.locator('#revoked-networks [data-ui-action="remove-network"]').click()
        assert '移除已撤销的网络' in page.locator('#dialog-title').inner_text()
        page.locator('#dialog-confirm').click()
        page.wait_for_function("() => !document.getElementById('revoked-networks')")
        assert decisions.count('remove-revoked') == 1
        page.unroute(control['origin']+'/api/command', presentation_mutation)
        feed['status'] = None
        page.unroute_all(behavior='wait')
        print('joining setup phase and persistent failure detail passed', flush=True)
        assert not errors, errors
        result = dict(version=page.evaluate('workspaceState.version'), overviewSelection=True,
            mouseDragAcrossRefresh=True, multilineLogSelection=True, pendingLogsCatchUp=True,
            inputSelection=True, dialogSelection=True, ipv4Default16=True, explicitIpv6Code36=True,
            newRequestBadgeWhileSelecting=True, joinSetupPhase=True, joinFailureVisible=True,
            decisionsRemoveCards=True, pendingRequestRemoval=True, revokedNetworkRemoval=True,
            committedJoinVisible=True, uuStateCompatible=True,
            uuExcludesUnapproved=True, uuTrafficConfirmation=True, updateDismissal=True,
            updateSuccessExpires=True, updateNoticeCleanup=True,
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
