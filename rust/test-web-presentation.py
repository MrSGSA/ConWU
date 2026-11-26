"""Exercise the real WebUI with an isolated memory backend (requires Playwright)."""
import argparse
import base64
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
parser.add_argument('--desktop-input', type=Path, help='Also verify native Windows mouse hit testing with this desktop shell')
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

def projection_interactions(page, feed, original):
    snapshot = copy.deepcopy(original)
    n = snapshot['networks'][0]
    peer = dict(deviceId='fixture-peer', name='测试桌面', connected=True, virtualIp='10.203.1.2', slot=1)
    n['status'].update(networkDirect=True, networkRevoked=False, directPeers=1, peers=[peer])
    p = dict(authorized=True, files=True, fileBrowser=True, companionReady=True, coverRevision='first',
             remoteSunshinePort=47989, port=48200, video={})
    n['status']['projection'] = p
    player = dict(available=True, networkId=None, opened=False)
    snapshot.update(projectionEmbedded=True, projectionBundled=True, projectionMoonlight=player)
    feed['status'] = snapshot
    cover_reads = []
    def projection_request(route):
        body = route.request.post_data_json
        assert body['deviceId'] == peer['deviceId'] and body['networkId'] == n['id']
        if route.request.url.endswith('/cover'):
            cover_reads.append(True)
            # A 1x1 24-bit BMP. No desktop is captured by this test.
            image = bytes.fromhex('424d3a00000000000000360000002800000001000000010000000100180000000000040000000000000000000000000000000000000000000000')
            value = dict(image=base64.b64encode(image).decode())
        elif route.request.url.endswith('/bitrate'):
            assert body['video']['scalePercent'] == 100
            value = dict(width=1920, height=1080, kbps=20000)
        else:
            action = body['request']
            kind = action['action']
            value = None
            if kind == 'list': value = dict(entries=[], path='C:\\', parent=dict(kind='drives'))
            else: raise AssertionError(kind)
        route.fulfill(json=dict(ok=True, value=value))
    pattern = control['origin']+'/api/projection/**'
    page.route(pattern, projection_request)
    def paint():
        page.evaluate('s=>render(s)', snapshot)
    paint()
    page.locator('#mode-switch').click()
    cover = page.locator('#projection-cover')
    page.wait_for_function("() => $('projection-cover')?.naturalWidth===1")
    assert cover.evaluate("e=>getComputedStyle(e).objectFit==='contain' && getComputedStyle(e).transform==='none'")
    assert not page.get_by_role('button', name='终端', exact=True).count()
    peer['connected'] = False
    paint()
    assert cover.is_hidden() and cover.get_attribute('src') is None
    assert page.get_by_role('button', name='未在线', exact=True).is_disabled()
    assert not page.get_by_text('等待 ConWU 直连', exact=True).count()
    peer['connected'] = True
    p['coverRevision'] = 'reconnect'
    paint()
    page.wait_for_function("() => !$('projection-cover').hidden")
    toolbar = page.locator('.projection-device-actions')
    fixed = toolbar.get_by_role('button', name='设置', exact=True)
    initial_position = fixed.bounding_box()
    player.update(networkId=n['id'], opened=False)
    paint()
    assert cover.is_visible()
    assert page.get_by_role('button', name='串流', exact=True).is_disabled()
    assert page.locator('#projection-stage-status').inner_text().startswith('正在准备串流')
    assert page.locator('.projection-progress-dots').evaluate("e=>getComputedStyle(e).animationName==='projection-progress-dots'")
    player['opened'] = True
    paint()
    assert cover.is_visible()
    page.evaluate('window.projectionVideo=[1280,1024]')
    page.wait_for_function("() => Math.abs($('projection-stage').offsetWidth/$('projection-stage').offsetHeight-1.25)<.015")
    page.wait_for_function("""() => {
        const stage = $('projection-stage');
        const rect = stage.getBoundingClientRect(), scale = devicePixelRatio;
        const edge = n => Math.round(n * scale), area = window.surfaceArea;
        const style = getComputedStyle(stage);
        return area?.showViewer && area.x === edge(rect.left) && area.y === edge(rect.top) &&
            area.x + area.width === edge(rect.right) && area.y + area.height === edge(rect.bottom) &&
            area.radius === 0 && style.borderTopLeftRadius === '0px' && style.borderLeftWidth === '0px' && style.boxShadow !== 'none';
    }""")
    size = page.locator('#projection-stage').evaluate('e=>[e.offsetWidth,e.offsetHeight]')
    playback = toolbar
    assert playback.get_by_role('button').all_text_contents() == ['设置', '文件互传', '全屏', '结束串流']
    assert fixed.bounding_box() == initial_position
    assert page.locator('.projection-hotkeys kbd').all_text_contents() == [
        'Ctrl+Alt+Shift+X', 'Ctrl+Alt+Shift+Z', 'Ctrl+Alt+Shift+Q', 'Ctrl+Shift+S',
    ]
    page.keyboard.press('Control+Shift+S')
    page.wait_for_function('() => statsToggles === 1')
    page.evaluate("busy=true;controls()")
    try:
        page.locator('[data-ui-action="projection-settings"]').click()
        assert page.locator('#projection-dialog').is_visible()
        page.locator('#projection-dialog [data-ui-action="close-projection-settings"]').click()
    finally:
        page.evaluate("busy=false;controls()")
    selected_text = select_text(page, '#page-title')
    page.evaluate("online=false;controls()")
    assert page.locator('[data-ui-action="projection-settings"]').is_enabled()
    page.evaluate("window.dispatchEvent(new Event('blur'));window.dispatchEvent(new Event('focus'))")
    paint()
    retained(page, selected_text)
    assert page.locator('[data-ui-action="projection-settings"]').is_enabled()
    clear_selection(page)
    for button, dialog in [('projection-settings','projection-dialog'), ('projection-file-browser','projection-file-dialog')]:
        page.locator('[data-ui-action="'+button+'"]').click()
        page.wait_for_function("() => window.surfaceArea?.showViewer && surfaceArea.cutouts.length===1")
        if dialog == 'projection-dialog':
            permissions = page.locator('#projection-dialog fieldset').filter(has_text='设备权限')
            assert permissions.get_by_role('checkbox').count() == 3
            assert permissions.get_by_role('checkbox', name='允许对机浏览并互传文件').is_checked()
            page.wait_for_function("() => $('projection-bandwidth').textContent.includes('20 Mb/s')")
            assert page.locator('#projection-scale').count() == 0
        page.locator('#'+dialog).press('Escape')
        page.wait_for_function("() => window.surfaceArea?.showViewer && !surfaceArea.cutouts.length")
    assert not page.get_by_role('button', name='端口映射', exact=True).count()
    command_path = control['origin']+'/api/command'
    def request_stop(route):
        payload = route.request.post_data_json
        assert payload['method'] == 'projection-stop' and payload['networkId'] == n['id']
        route.fulfill(json=dict(ok=True, status=snapshot))
    page.route(command_path, request_stop)
    with page.expect_request(lambda request: request.url == command_path):
        page.keyboard.press('Control+Alt+Shift+Q')
    page.wait_for_function("() => $('projection-stage-status')?.textContent.startsWith('正在结束') && !busy")
    page.wait_for_function("() => surfaceArea?.showViewer && surfaceArea.acceptInput===false")
    page.unroute(command_path, request_stop)
    assert cover.is_visible() and cover.get_attribute('src').startswith('data:image/')
    assert playback.get_by_role('button', name='结束串流', exact=True).is_disabled()
    assert page.locator('#projection-stage-status').inner_text().startswith('正在结束')
    # The native window completes before the next backend status update.
    page.evaluate('window.projectionEnded=true')
    page.wait_for_function('() => window.projectionEndingHandoffs.length===1')
    assert page.evaluate('window.projectionEndingHandoffs[0]') == dict(visibleCover=True, endingLabel=False)
    assert page.get_by_role('button', name='串流', exact=True).is_disabled()
    player.update(networkId=None, opened=False, stopping=False)
    paint()
    assert cover.is_visible()
    assert len(cover_reads) == 2
    p['coverRevision'] = 'stopped'
    with page.expect_response(lambda response: response.url.endswith('/api/projection/cover')):
        paint()
    page.wait_for_function("() => !$('projection-cover').hidden")
    page.wait_for_function('() => !surfaceArea?.showViewer')
    settings = page.locator('[data-ui-action="projection-settings"]')
    settings.hover()
    assert settings.evaluate("e=>getComputedStyle(e).cursor==='pointer'")
    settings.click()
    assert page.locator('#projection-dialog').is_visible()
    page.locator('#projection-dialog').press('Escape')
    assert len(cover_reads) == 3
    peer['connected'] = False
    paint()
    assert cover.is_hidden()
    offline_size = page.locator('#projection-stage').evaluate('e=>[e.offsetWidth,e.offsetHeight]')
    assert all(abs(a-b)<=1 for a,b in zip(size, offline_size))
    stored = page.evaluate("""key=>JSON.parse(localStorage.getItem('conwu-projection-size-'+JSON.stringify(key)))""",
                           [n['id'], peer['deviceId']])
    assert stored['video'] == [1280, 1024] and stored['window'] == size
    viewport = page.viewport_size
    page.set_viewport_size({'width': viewport['width'], 'height': viewport['height'] + 150})
    assert page.locator('#projection-stage').evaluate('e=>[e.offsetWidth,e.offsetHeight]') == offline_size
    page.set_viewport_size(viewport)
    other = copy.deepcopy(n)
    other['id'] = uuid.uuid4().hex
    other['status']['peers'][0].update(deviceId='next-peer', name='另一台设备', connected=True)
    other['status']['projection']['coverRevision'] = None
    snapshot['networks'] = [other]
    player.update(networkId=n['id'], opened=False, stopping=True)
    paint()
    assert page.locator('#page-title').inner_text() == '另一台设备'
    assert not page.locator('#projection-stage-status').count()
    assert cover.is_hidden()
    page.locator('#mode-switch').click()
    page.unroute(pattern, projection_request)
    print('Projection preview, focus, modal placement and tools passed', flush=True)

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
        page = browser.new_page(viewport={'width': 1240, 'height': 850}, device_scale_factor=1.25)
        page.add_init_script('''window.statsToggles=0;window.projectionVideo=null;
window.projectionEnded=false;window.projectionEndingHandoffs=[];
window.conwuProjectionSurface=async (area, closeEnded, fullscreen, stats)=>{
    window.surfaceArea=area;
    if (stats) window.statsToggles++;
    if (closeEnded) {
        if (area || !window.projectionEnded) throw Error('Unexpected native ending acknowledgement');
        window.projectionEndingHandoffs.push({
            visibleCover:document.querySelector('#projection-cover')?.hidden===false,
            endingLabel:document.querySelector('#projection-stage-status')?.textContent.startsWith('正在结束')===true,
        });
        window.projectionEnded=false;
    }
    return {fullscreen:false,video:window.projectionVideo,ended:window.projectionEnded};
}''')
        page.set_default_timeout(10000)
        page.on('pageerror', lambda error: errors.append(str(error)))
        if args.source_assets:
            assets = ROOT / 'src/ConWU.Web/wwwroot'
            def edited(route):
                name = route.request.url.split('?')[0].removeprefix(control['origin']).strip('/') or 'index.html'
                response = route.fetch()
                route.fulfill(response=response, body=(assets / name).read_bytes())
            for path in ('/', '/app.js', '/workspace.js', '/uu-takeover.js', '/experience.js',
                         '/projection.js','/projection-files.js','/projection.css','/experience.css'):
                page.route(control['origin'] + path, edited)
        page.goto(url)
        page.wait_for_function('() => workspaceState?.workspaceVersion === 1')
        assert page.evaluate("""() => {
            const pages=['overview','create','join','exit','requests','coordination','uu'];
            return new Set(pages.map(p=>getComputedStyle(document.querySelector('.nav[data-page="'+p+'"] .icon')).color)).size;
        }""") == 7
        if not args.source_assets:
            for asset in page.locator('script[src], link[rel="stylesheet"]').all():
                path = asset.get_attribute('src') or asset.get_attribute('href')
                response = page.request.get(control['origin'] + path)
                assert response.ok, f'{path} returned HTTP {response.status}'
            assert page.evaluate('typeof projectionFiles === "object"')

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
        page.evaluate("""() => {
            const real=structuredClone(workspaceState), snapshot=structuredClone(real);
            const base=snapshot.networks[0] || {name:'scroll',status:{
                settings:{pathSelection:'tcp-only',listenPort:24680},networkEnabled:true,virtualIp:'10.0.1.1',
                peers:[],networkId:'scroll',isOwner:true
            }};
            snapshot.networks=Array.from({length:16},(_,i)=>({...base,id:'scroll-'+i}));
            render(snapshot);
            window.scrollTo(0,250);
            const top=window.scrollY, node=$('page-title');
            snapshot.aggregate.sentBytes+=100;
            render(snapshot);
            if(top<1||window.scrollY!==top||$('page-title')!==node)throw Error('流量刷新重建了概况或复位滚动条');
            render(real);window.scrollTo(0,0);
        }""")
        print('overview chart preserves scroll and mounted controls', flush=True)

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
        page.locator('#auto-scroll').uncheck()
        before_scroll = page.evaluate("""() => {
            for(let i=0;i<90;i++)appendLogLine('scroll-fixture-'+i,'fixture',Date.now());
            updateLogView();const t=$('terminal-content');
            t.scrollTop=12;window.testLogTerminal=t;return t.scrollTop;
        }""")
        assert before_scroll > 0
        page.evaluate("() => {const s=structuredClone(workspaceState);s.deviceName+=' changed';render(s);}")
        assert page.evaluate("() => $('terminal-content')===window.testLogTerminal && $('terminal-content').scrollTop") == before_scroll
        page.locator('#auto-scroll').check()
        search = page.locator('#log-search')
        search.fill('selection-regression')
        search.evaluate('(input) => {input.setSelectionRange(2,10);window.__selectedInput=input;}')
        tick(page)
        assert page.evaluate('window.__selectedInput.isConnected && window.__selectedInput.selectionStart===2 && window.__selectedInput.selectionEnd===10')
        search.press('ArrowRight')
        clear_selection(page)
        page.locator('button[data-page="create"]').first.click()

        page.locator('button[data-ui-action="open-editor"][data-network=""]').click()
        page.locator('button[data-ui-section="stun"]').click()
        stun = page.locator('textarea[data-key="tcp"]')
        assert stun.input_value().splitlines() == page.evaluate('workspaceState.networkDefaults.tcpStun')
        assert page.locator('#settings-fields input[type=checkbox]').count() == 0
        stun.fill('stun.example.com:3478')
        page.locator('#network-dialog [data-ui-action="close-editor"]').first.click()
        assert page.locator('#network-dialog').is_hidden() and page.locator('#confirm-dialog').is_hidden()
        page.locator('button[data-ui-action="open-editor"][data-network=""]').click()
        page.locator('button[data-ui-section="stun"]').click()
        assert stun.input_value().splitlines() == page.evaluate('workspaceState.networkDefaults.tcpStun')
        page.locator('button[data-ui-section="port"]').click()
        assert page.locator('#settings-fields input[type=checkbox]').count() == 0
        page.locator('button[data-ui-section="network"]').click()
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
        if not args.source_assets:
            owned = page.evaluate('workspaceState.networks[0]')
            record = owned['id']
            wire = owned['status']['networkId']
            command(dict(method='network', networkId=record, network=dict(action='pause-network', cold=True)))
            page.wait_for_function("id => workspaceState.networks.find(n=>n.id===id)?.status.networkEnabled===false", arg=record)
            command(dict(method='start', networkId=record))
            page.wait_for_function("""({id,wire}) => {
                const s = workspaceState.networks.find(n=>n.id===id)?.status;
                return s?.networkId===wire && s.networkEnabled;
            }""", arg=dict(id=record, wire=wire))
            print('cold network stop and resume preserves the network identity', flush=True)
        original_status = page.evaluate('JSON.parse(JSON.stringify(workspaceState))')
        if args.desktop_input:
            from test_desktop_input import exercise
            exercise(args.desktop_input.resolve(), original_status, data)
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
        projection_interactions(page, feed, original_status)
        feed['status'] = incoming
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
            elif body.get('method') == 'network' and action in ('disconnect', 'reconnect'):
                row = feed['status']['networks'][0]
                assert body['networkId'] == row['id'] and body['network']['expectedNetwork'] == row['status']['networkId']
                row['status']['networkEnabled'] = action == 'reconnect'
                decisions.append(action)
            elif body.get('method') == 'network' and action in ('leave', 'delete-network', 'remove-network'):
                rows = feed['status']['networks']
                target = next(n for n in rows if n['id'] == body['networkId'])
                status = target['status']
                assert body['network']['confirmReplace'] and body['network']['expectedNetwork'] == status['networkId']
                assert bool(status.get('networkRevoked')) == (action == 'remove-network')
                assert bool(status.get('isOwner')) == (action == 'delete-network')
                feed['status']['networks'] = [n for n in rows if n['id'] != target['id']]
                decisions.append(action if status['networkId'] else 'remove-revoked' if action == 'remove-network' else 'remove-request')
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
        paired = copy.deepcopy(original_status)
        paired['networks'][0]['status'].update(isOwner=False, networkEnabled=True)
        feed['status'] = paired
        page.evaluate('s=>render(s)', paired)
        page.locator('button[data-page="join"]').first.click()
        joined = page.locator('#joined-networks .network-entry').first
        disconnect = joined.get_by_role('button', name='断开连接', exact=True)
        disconnect.click()
        assert page.locator('#confirm-dialog').is_hidden()
        reconnect = joined.get_by_role('button', name='重新连接', exact=True)
        page.wait_for_function("() => !busy && !!document.querySelector('#joined-networks [data-ui-action=reconnect-network]')")
        reconnect.click()
        page.wait_for_function("() => !busy && !!document.querySelector('#joined-networks [data-ui-action=disconnect-network]')")
        assert decisions.count('disconnect') == decisions.count('reconnect') == 1

        owner = copy.deepcopy(original_status['networks'][0])
        owner.update(id=uuid.uuid4().hex, name='本机创建的测试网络')
        owner['status']['networkId'] = uuid.uuid4().hex
        paired['networks'].append(owner)
        page.evaluate('s=>render(s)', paired)
        page.locator('button[data-page="exit"]').first.click()
        assert page.get_by_text('退出网络并删除本机在网络中的信息', exact=True).is_visible()
        assert page.locator('#content select').count() == 0
        exit_rows = page.locator('.network-exit-card .network-entry')
        assert exit_rows.count() == 2
        member_exit = exit_rows.filter(has=page.get_by_text('本机加入', exact=True))
        member_exit.get_by_role('button', name='退出', exact=True).click()
        assert page.locator('#confirm-dialog').is_hidden()
        page.wait_for_function("() => !busy && document.querySelectorAll('.network-exit-card .network-entry').length===1")
        assert decisions.count('leave') == 1 and 'delete-network' not in decisions

        page.locator('button[data-page="create"]').first.click()
        owned = page.locator('#owned-networks .network-entry').filter(has_text=owner['name'])
        remove = owned.get_by_role('button', name='删除网络', exact=True)
        remove.click()
        assert page.locator('#page-title').inner_text() == '创建网络'
        assert page.locator('#confirm-dialog').is_hidden()
        page.wait_for_function("() => !busy && !document.querySelector('#owned-networks .network-entry')")
        assert decisions.count('delete-network') == 1
        print('Single-click delete, disconnect and exit actions passed', flush=True)
        page.locator('button[data-page="requests"]').first.click()

        for decision in ('approve', 'reject'):
            feed['status'] = copy.deepcopy(incoming)
            feed['status']['networks'][0]['status']['pairing']['pending'] = True
            tick(page, 1)
            page.locator('[data-ui-action="'+decision+'"]').click()
            page.wait_for_function("() => document.getElementById('content').textContent.includes('暂无加入申请')")
            assert page.locator('#requests-count').is_hidden()
        assert decisions == ['disconnect', 'reconnect', 'leave', 'delete-network', 'approve', 'reject']
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
        page.wait_for_function("() => document.querySelector('#join-card .join-progress strong')?.textContent==='正在联系主机'")
        assert page.locator('#join-submit').is_visible()
        assert page.locator('#join-card').get_by_role('button', name='取消加入').is_visible()
        assert page.locator('#unapproved-requests').count() == 0
        # The membership may already be committed while the guest retries the
        # delivery acknowledgement. Show the joined state as soon as it exists.
        guest['status'].update(networkId=uuid.uuid4().hex, directPeers=1)
        tick(page, 1)
        assert page.locator('#join-card .join-progress strong').inner_text() == '已加入 ' + guest['name']
        guest['status'].update(networkId='', directPeers=0)
        message = '本机 Mimic XDP 队列检查失败（隔离测试）'
        guest['status']['pairing'].update(active=False, error=message, state=message)
        tick(page, 1)
        assert page.locator('#join-error').inner_text() == message
        assert page.locator('#join-submit').is_visible()
        assert page.locator('#join-invite').input_value().replace('-', '') == ipv4_code
        page.unroute(control['origin']+'/api/command', injected_join)
        assert page.locator('#unapproved-requests').count() == 0
        page.locator('button[data-page="exit"]').first.click()
        exit_rows = page.locator('.network-exit-card .network-entry')
        exit_rows.get_by_role('button', name='移除申请', exact=True).click()
        page.wait_for_function("() => !busy && !document.querySelector('.network-exit-card .network-entry')")
        assert decisions.count('remove-request') == 1

        guest['status'].update(networkRevoked=True, state='主机已撤回本机授权', pairing=None)
        pending['networks'] = [guest]
        tick(page, 1)
        exit_rows.get_by_role('button', name='移除记录', exact=True).click()
        assert page.locator('#confirm-dialog').is_hidden()
        page.wait_for_function("() => !busy && !document.querySelector('.network-exit-card .network-entry')")
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
            committedJoinVisible=True, inlineNetworkActions=True, projectionEndingHandoff=True, uuStateCompatible=True,
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
