"""Exercise an isolated MSI instance using the current user's filtered token.

Never targets the installed daily service. Evidence contains public status and
checks only; service identities remain inaccessible to the interactive user.
"""
import argparse
import base64
import ctypes as c
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent


def filtered(command):
    script = '& ' + ' '.join("'" + v.replace("'", "''") + "'" for v in command) + '; exit $LASTEXITCODE'
    encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
    subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File',
        str(ROOT / 'rust/Run-FilteredUser.ps1'), '-EncodedCommand', encoded,
        '-WorkingDirectory', str(ROOT)], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--instance', required=True)
    parser.add_argument('--child', action='store_true')
    parser.add_argument('--create', action='store_true')
    parser.add_argument('--start-stopped', action='store_true')
    parser.add_argument('--tray', action='store_true')
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    if uuid.UUID(args.instance).hex != args.instance:
        raise ValueError('Canonical isolated instance required')
    args.evidence = args.evidence.resolve()
    if not args.evidence.is_relative_to(ROOT / 'out'):
        raise ValueError('Evidence must be within this worktree/out')
    if not args.child:
        filtered([sys.executable, str(Path(__file__).resolve()), *sys.argv[1:], '--child'])
        print(args.evidence.read_text(encoding='utf-8'))
        return
    evidence = {}
    try:
        shell = c.WinDLL('shell32')
        assert not shell.IsUserAnAdmin(), 'Test must use a non-elevated user'
        evidence['ordinaryUser'] = True
        private = Path(os.environ['ProgramData']) / 'ConWU-Validation' / args.instance / 'database.private.json'
        try:
            private.read_bytes()
        except PermissionError:
            evidence['privateDataDenied'] = True
        else:
            raise AssertionError('Ordinary user could read service identities')
        exe = Path(os.environ['ProgramFiles']) / 'StreamLink-Validation' / args.instance / 'msi/app/ConWU.exe'
        def cli(*command):
            reply = subprocess.run([str(exe), '--validation-instance', args.instance, *command],
                capture_output=True, text=True, encoding='utf-8', timeout=150)
            if reply.returncode:
                raise RuntimeError(reply.stderr[-1600:])
            return json.loads(reply.stdout)
        if args.start_stopped:
            subprocess.run(['sc.exe','start','StreamLink-Validation-'+args.instance],check=True,capture_output=True)
            evidence['ordinaryUserStartedService'] = True
        deadline = time.monotonic() + 230
        while True:
            try:
                state = cli('status')
                if all(n['status']['adapter']['ready'] for n in state['networks']):
                    break
            except (RuntimeError, subprocess.TimeoutExpired):
                pass
            if time.monotonic() > deadline:
                raise TimeoutError('Service/adapters did not become ready')
            time.sleep(.5)
        evidence['brokerStatus'] = state['serviceReady']
        if args.create:
            assert not state['networks'], 'Create phase requires a fresh validation instance'
            settings = state['networkDefaults']
            settings.update(pathSelection='tcp-only', connectionSource='existing', discoveryMode='existing',
                listenPort=27820, sourcePort=27821, portControlMapping=False, pkarrPublish=False,
                existingEntries=[{'peerSlot': 0, 'source': '192.168.127.250:27820'}])
            config_file = args.evidence.with_suffix('.settings.json')
            config_file.write_text(json.dumps(settings), encoding='utf-8')
            for index in range(2):
                profile = cli('profile', 'create', 'MSI independent ' + str(index), str(config_file))
                cli('network', 'create', profile['configurationId'], 'MSI independent ' + str(index))
        state = cli('status')
        assert len(state['networks']) == 2
        ports, networks = [], []
        configurations = {v['id']: v for v in state['configurations']}
        for network in state['networks']:
            row = network['status']
            assert row['adapter']['ready'], 'Installed adapter did not start'
            settings = configurations[network['configurationId']]['settings']
            assert settings['listenPort'] == row['settings']['listenPort'], 'Saved editor port differs from listener'
            ports.append(settings['listenPort'])
            networks.append({'id': network['id'], 'virtualIp': row['virtualIp'], 'port': ports[-1]})
        assert len(set(ports)) == 2, 'Independent networks reused the same port'
        evidence.update(networks=networks, independentPorts=True, adaptersReady=True)
        if args.tray:
            tray_log=args.evidence.with_suffix('.tray.log').open('wb')
            process=subprocess.Popen([str(exe),'--validation-instance',args.instance,'tray','--no-open'],
                stdout=tray_log,stderr=subprocess.STDOUT,creationflags=subprocess.CREATE_NO_WINDOW)
            try:
                user=c.WinDLL('user32',use_last_error=True)
                user.FindWindowExW.argtypes=[c.c_void_p,c.c_void_p,c.c_wchar_p,c.c_wchar_p]
                user.FindWindowExW.restype=c.c_void_p
                user.GetWindowThreadProcessId.argtypes=[c.c_void_p,c.POINTER(c.c_ulong)]
                user.PostMessageW.argtypes=[c.c_void_p,c.c_uint,c.c_size_t,c.c_ssize_t]
                import hashlib
                data=str(private.parent).lower()
                title='\\\\.\\pipe\\ConWU.Rust.Control.'+hashlib.sha256(data.encode()).hexdigest()[:24]
                deadline=time.monotonic()+35
                window=None
                while time.monotonic()<deadline:
                    for parent in (None,c.c_void_p(-3)):
                        found=user.FindWindowExW(parent,None,None,title)
                        if found:
                            pid=c.c_ulong()
                            user.GetWindowThreadProcessId(found,c.byref(pid))
                            if pid.value==process.pid: window=found; break
                    if window: break
                    time.sleep(.2)
                assert window and process.poll() is None, 'Tray window did not start under the ordinary user (exit='+str(process.poll())+')'
                assert user.PostMessageW(window,0x10,0,0), 'Tray rejected close'
                assert process.wait(timeout=8)==0, 'Tray did not exit cleanly'
                evidence['ordinaryUserTrayLifecycle']=True
            finally:
                if process.poll() is None: process.terminate();process.wait(timeout=5)
                tray_log.close()
    except Exception as error:
        evidence['error'] = str(error)
        raise
    finally:
        args.evidence.write_text(json.dumps(evidence, indent=2, ensure_ascii=False), encoding='utf-8')


if __name__ == '__main__':
    main()
