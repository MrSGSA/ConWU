"""Windows Wintun / Linux TUN cross-platform carrier and recovery gate.

Uses only fresh stores and uniquely named temporary firewall rules. The Linux
process runs in WSL; installed production services and their stores are unused.
No payload, pairing secret or private identity is printed to the console.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent
WSL_ROOT = '/mnt/' + ROOT.drive[0].lower() + ROOT.as_posix()[2:]


def ps(script):
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                            text=True, capture_output=True, encoding='utf-8', errors='replace')
    if result.returncode:
        raise RuntimeError(result.stderr[-1800:])
    return result.stdout


def wait(label, condition, timeout=45):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if condition():
            return
        time.sleep(.25)
    raise TimeoutError(label)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('modes', nargs='*', choices=['tcp', 'https', 'mimic', 'phantun', 'tcpraw', 'faketcp'])
    parser.add_argument('--dependency-root', type=Path, default=ROOT.parent / 'ConWU-Converged/out/dependency-cache')
    parser.add_argument('--restart', action='store_true')
    args = parser.parse_args()
    if os.name != 'nt':
        raise RuntimeError('Run this gate on Windows with the ArchLinux WSL distribution')
    token = uuid.uuid4().hex[:8]
    folder = ROOT / 'out/lab' / ('cross-' + token)
    folder.mkdir(parents=True)
    linux_folder = WSL_ROOT + '/out/lab/' + folder.name
    components = folder / 'components'
    components.mkdir()
    for name, source in {
        'conwu-raw.exe': ROOT / 'out/rust-target/release/conwu-raw.exe',
        'conwu-phantun.exe': ROOT / 'out/rust-target/release/conwu-phantun.exe',
        'udp2raw-native.exe': ROOT / 'out/native/udp2raw-native.exe',
        'wintun.dll': args.dependency_root / 'wintun/bin/amd64/wintun.dll',
        'WinDivert.dll': args.dependency_root / 'WinDivert-2.2.2-A/x64/WinDivert.dll',
        'WinDivert64.sys': args.dependency_root / 'WinDivert-2.2.2-A/x64/WinDivert64.sys',
        'xdpapi.dll': args.dependency_root / 'xdp-1.4.0/unpacked/runtime/native/xdpapi.dll',
    }.items():
        if source.is_symlink() or not source.is_file():
            raise ValueError('Missing/linked component: ' + str(source))
        shutil.copyfile(source, components / name)
    addresses = json.loads(subprocess.check_output(['wsl', '-d', 'ArchLinux', '-u', 'root', '--',
        'ip', '-j', '-4', 'addr', 'show', 'eth0'], text=True))
    linux_ip = addresses[0]['addr_info'][0]['local']
    ipaddress.IPv4Address(linux_ip)
    executable = ROOT / 'out/rust-target/debug/conwu.exe'
    commands = [
        [str(executable), 'run', '--data', str(folder / 'windows'), '--components', str(components), '--no-open', '--no-tray'],
        ['wsl', '-d', 'ArchLinux', '-u', 'root', '--', WSL_ROOT + '/out/rust-target-linux/debug/conwu', 'run',
         '--data', linux_folder + '/linux', '--components', WSL_ROOT + '/out/rust-components-linux', '--no-open', '--no-tray'],
    ]
    processes = [None, None]
    logs = []
    rules = []
    results = []

    def start(index):
        log = (folder / ('process-' + str(index) + '.log')).open('ab')
        logs.append(log)
        processes[index] = subprocess.Popen(commands[index], stdout=log, stderr=log,
                                            creationflags=subprocess.CREATE_NO_WINDOW)
        wait('control start', lambda: (folder / ('windows' if index == 0 else 'linux') / 'panel.private.json').exists()
             and processes[index].poll() is None)

    def rpc(index, body):
        if index == 0:
            command = ['python', str(ROOT / 'rust/lab-client.py'), str(folder / 'windows'), '-']
        else:
            command = ['wsl', '-d', 'ArchLinux', '-u', 'root', '--', 'python3', WSL_ROOT + '/rust/lab-client.py', linux_folder + '/linux', '-']
        result = subprocess.run(command, input=json.dumps(body), capture_output=True, text=True,
                                encoding='utf-8', errors='replace', timeout=100)
        if result.returncode:
            raise RuntimeError('Control ' + body.get('method', '') + ': ' + result.stderr[-1600:])
        return json.loads(result.stdout)

    def stop(index):
        process = processes[index]
        if process is None:
            return
        if process.poll() is None:
            try:
                rpc(index, {'method': '_stop'})
                process.wait(timeout=70)
            except Exception:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=10)
        processes[index] = None

    def row(index, identity):
        return next(n['status'] for n in rpc(index, {'method': '_status'})['status']['networks'] if n['id'] == identity)

    def ping(index, target):
        command = ['ping', '-n', '3', '-w', '2000', '-l', '1000', target] if index == 0 else [
            'wsl', '-d', 'ArchLinux', '-u', 'root', '--', 'ping', '-n', '-c', '3', '-W', '2', '-s', '1000', target]
        result = subprocess.run(command, capture_output=True)
        if result.returncode:
            raise RuntimeError('Bidirectional TUN ping failed on side ' + str(index))

    try:
        start(0)
        start(1)
        for offset, mode in enumerate(args.modes or ['tcp', 'https', 'phantun', 'mimic', 'tcpraw', 'faketcp']):
            begin = time.monotonic()
            listen = 48900 + offset * 10
            settings = rpc(1, {'method': '_status'})['status']['networkDefaults']
            settings.update(pathSelection=mode + '-only', connectionSource='existing', discoveryMode='existing',
                            listenPort=listen, sourcePort=listen + 1,
                            existingEntries=[{'peerSlot': 0, 'source': linux_ip + ':' + str(listen)}])
            config = rpc(1, {'method': 'configuration', 'configuration': {
                'action': 'save', 'id': '', 'name': 'Cross ' + mode, 'expectedRevision': 0, 'settings': settings}})
            created = rpc(1, {'method': 'network', 'network': {
                'action': 'create-direct', 'name': 'Cross ' + mode, 'configurationId': config['configurationId'], 'mode': mode}})
            host = created['status']['selectedNetworkId']
            invitation = rpc(1, {'method': 'network', 'networkId': host, 'network': {'action': 'invite-compact', 'expectedNetwork': host}})
            code = next(n['status']['pairing']['code'] for n in invitation['status']['networks'] if n['id'] == host)
            joined = rpc(0, {'method': 'network', 'network': {'action': 'join-compact', 'code': code, 'name': 'Cross Windows'}})
            guest = joined['status']['selectedNetworkId']
            wait('SAS ' + mode, lambda: len(row(1, host)['pairing'].get('verification', '')) == 6)
            pending = row(1, host)['pairing']
            rpc(1, {'method': 'network', 'networkId': host, 'network': {
                'action': 'approve', 'verification': pending['verification'], 'candidate': pending['candidate']}})
            wait('direct ' + mode, lambda: row(1, host)['directPeers'] == 1 and row(0, guest)['directPeers'] == 1)
            h, g = row(1, host), row(0, guest)
            for value in (g['virtualIp'], h['virtualIp']):
                ipaddress.IPv4Address(value)
            rule = 'ConWU-Rust-Cross-' + token + '-' + mode
            ps("$null=New-NetFirewallRule -Name '" + rule + "' -DisplayName 'ConWU isolated TUN test' -Direction Inbound -Action Allow -Protocol ICMPv4 -IcmpType 8 -LocalAddress '" + g['virtualIp'] + "' -RemoteAddress '" + h['virtualIp'] + "' -Profile Any")
            rules.append(rule)
            ping(0, h['virtualIp'])
            ping(1, g['virtualIp'])
            # A paused network retains its identity/discovery, then reconnects.
            rpc(0, {'method': 'network', 'networkId': guest, 'network': {'action': 'disconnect'}})
            rpc(0, {'method': 'network', 'networkId': guest, 'network': {'action': 'reconnect'}})
            wait('reconnect ' + mode, lambda: row(1, host)['directPeers'] == 1 and row(0, guest)['directPeers'] == 1)
            ping(0, h['virtualIp'])
            if args.restart:
                stop(0)
                for name in ('panel.private.json', 'lab-session.private.json'):
                    path = folder / 'windows' / name
                    if path.is_file() and not path.is_symlink():
                        path.unlink()
                start(0)
                wait('restart restore ' + mode, lambda: row(0, guest)['directPeers'] == 1)
                ping(0, h['virtualIp'])
            result = {'mode': mode, 'windowsAdapter': g['adapter'], 'linuxAdapter': h['adapter'],
                      'pairing': True, 'bidirectionalTun': True, 'reconnect': True,
                      'restart': args.restart, 'seconds': round(time.monotonic() - begin, 2)}
            results.append(result)
            print(json.dumps(result), flush=True)
            (ROOT / 'out/windows-linux-lab-result.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    finally:
        for index in range(2):
            stop(index)
        for rule in rules:
            ps("Get-NetFirewallRule -Name '" + rule + "' -ErrorAction SilentlyContinue | Remove-NetFirewallRule")
        for log in logs:
            log.close()


if __name__ == '__main__':
    main()
