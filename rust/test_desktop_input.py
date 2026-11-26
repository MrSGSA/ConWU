"""Exercise desktop mouse routing without clicking the user's desktop or using a production backend."""
import copy
import ctypes as ct
from ctypes import wintypes
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
from queue import Queue, Empty
import subprocess
from threading import Thread
import time


def exercise(shell, original, data):
    status = copy.deepcopy(original)
    n = status['networks'][0]
    n['status'].update(isOwner=True, networkDirect=True, networkRevoked=False, pairing=None,
                       peers=[dict(deviceId='test', name='测试桌面', connected=True, slot=1, virtualIp='10.203.1.2')])
    n['status']['projection'] = dict(authorized=True, files=True, fileBrowser=True, companionReady=True, video={})
    status.update(projectionEmbedded=True, projectionBundled=True, projectionMoonlight=dict(available=True))
    assets = Path(__file__).resolve().parents[1] / 'src/ConWU.Web/wwwroot'

    events = Queue()
    script = b"""
    (async () => {
      let point='',events=[];
      for(const kind of ['pointerdown','pointerup','click']){
        document.addEventListener(kind,e=>{events.push([kind,e.target.closest('button')?.dataset,e.clientX,e.clientY]);if(events.length>5)events.shift()},true);
      }
      const emit = value => fetch('/native-input-event', {method:'POST', body:JSON.stringify(value)});
      const wait = async test => {
        for(let i=0;i<200;i++){if(test())return;await new Promise(r=>setTimeout(r,40));}
        throw Error('Native click did not complete the expected transition');
      };
      const visible = selector => !!document.querySelector(selector)?.getClientRects().length;
      const click = async (selector, reached, churn=false) => {
        await wait(()=>visible(selector)&&!document.querySelector(selector).disabled);
        const b=document.querySelector(selector);
        b.scrollIntoView({block:'nearest'});
        point=selector;
        let rect=b.getBoundingClientRect(),x=rect.left+rect.width/2,y=rect.top+rect.height/2;
        if(!b.contains(document.elementFromPoint(x,y))||getComputedStyle(b).cursor!=='pointer')
          throw Error('WebView target does not accept input: '+selector);
        if(churn)b.addEventListener('pointerdown',()=>{let s=structuredClone(workspaceState);
          s.networks[0].name+='x';render(s);},{once:true});
        await emit({point:[x*devicePixelRatio,y*devicePixelRatio],selector});
        await wait(reached);
      };
      try {
        await wait(()=>typeof workspaceState!=='undefined'&&workspaceState?.version&&projectionMode.desktop);
        await click('button.nav[data-page=create]',()=>visible('#create-form'));
        for(let i=0;i<3;i++){
          await click('button.btn[data-ui-action=select-host]',()=>visible('#invitation-dialog'),true);
          await click('button[data-ui-action=close-invitation]',()=>!visible('#invitation-dialog'));
          await click('#mode-switch',()=>visible('#projection-stage'));
          await click('button[data-ui-action=projection-settings]',()=>visible('#projection-dialog'),true);
          await click('button[data-ui-action=close-projection-settings]',()=>!visible('#projection-dialog'));
          await click('#mode-switch',()=>visible('#create-form'));
        }
        await emit({done:true});
      }catch(e){await emit({error:String(e),point,page:typeof page==="undefined"?"unknown":page,events});}
    })();
    """
    class Fixture(SimpleHTTPRequestHandler):
        def reply(self, value):
            data = json.dumps(value).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path in ('/', '/index.html', '/native-input-test.js'):
                asset = self.path == '/native-input-test.js'
                content = script if asset else (assets/'index.html').read_bytes().replace(
                    b'</body>', b'<script defer src="/native-input-test.js"></script></body>')
                self.send_response(200)
                self.send_header('Content-Type', 'application/javascript' if asset else 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            elif self.path.split('?')[0] == '/api/status':
                self.reply(dict(ok=True, status=status))
            elif self.path == '/api/session':
                self.reply(dict(csrf='fixture'))
            else:
                super().do_GET()

        def do_POST(self):
            if self.path == '/native-input-event':
                length = int(self.headers.get('Content-Length','0'))
                if self.headers.get('Origin') != f'http://127.0.0.1:{self.server.server_port}' or not 0 < length <= 4096:
                    self.send_error(400)
                    return
                events.put(json.loads(self.rfile.read(length)))
                self.reply({})
            elif self.path == '/api/session':
                self.reply(dict(csrf='fixture'))
            else:
                self.send_error(405)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), partial(Fixture, directory=str(assets)))
    Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    env = dict(os.environ, CONWU_DESKTOP_PROFILE=str(data / 'desktop-profile'))
    desktop = subprocess.Popen([str(shell), '--panel', '--desktop-only'], stdin=subprocess.PIPE,
                               env=env, creationflags=subprocess.BELOW_NORMAL_PRIORITY_CLASS)
    user = ct.windll.user32
    hwnd = None
    try:
        desktop.stdin.write(f'http://127.0.0.1:{port}/#{secrets.token_hex(32).upper()}'.encode())
        desktop.stdin.close()
        for _ in range(100):
            hwnd = user.FindWindowW(f'ConWU.Desktop.{port}', None)
            if hwnd: break
            assert desktop.poll() is None, 'isolated desktop shell exited'
            time.sleep(.1)
        assert hwnd, 'isolated desktop window not found'
        user.ChildWindowFromPointEx.argtypes = [wintypes.HWND, wintypes.POINT, wintypes.UINT]
        user.ChildWindowFromPointEx.restype = wintypes.HWND
        user.SetThreadDpiAwarenessContext.argtypes = [wintypes.HANDLE]
        user.SetThreadDpiAwarenessContext.restype = wintypes.HANDLE
        prior_dpi = user.SetThreadDpiAwarenessContext(-4)
        assert prior_dpi, 'native test coordinates must use physical pixels' 
        try:
            steps = 0
            while True:
                try:
                    event = events.get(timeout=15)
                except Empty:
                    raise AssertionError(f'No native input acknowledgement after {steps} clicks')
                if "error" in event: raise AssertionError((steps,event))
                if event.get('done'): break
                x, y = event['point']
                selector = event['selector']
                pt = wintypes.POINT(round(x), round(y))
                target = hwnd
                while True:
                    child = user.ChildWindowFromPointEx(target, pt, 7)
                    if not child or child == target:
                        break
                    user.MapWindowPoints(target, child, ct.byref(pt), 1)
                    target = child
                name = ct.create_unicode_buffer(128)
                user.GetClassNameW(target, name, 128)
                assert name.value.startswith('Chrome_'), ('native hit intercepted', name.value, selector)
                pos = (pt.y << 16) | (pt.x & 0xffff)
                user.PostMessageW(target, 0x200, 0, pos)
                user.PostMessageW(target, 0x201, 1, pos)
                user.PostMessageW(target, 0x202, 0, pos)
                steps += 1
            assert steps == 19
            print('Native WebView2 mouse hit, press across refresh, invitation and mode switching passed', flush=True)
        finally:
            user.SetThreadDpiAwarenessContext(prior_dpi)
    finally:
        if hwnd:
            user.PostMessageW(hwnd, 0x10, 0, 0)
        try:
            desktop.wait(timeout=4)
        except subprocess.TimeoutExpired:
            desktop.terminate()
            desktop.wait(timeout=6)
        server.shutdown()
        server.server_close()
