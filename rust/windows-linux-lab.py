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
    parser.add_argument('--managed', action='store_true', help='Require the signed SLF1/SLN1 path; test builds only')
    parser.add_argument('--assisted', action='store_true', help='Require the same-source coordinated pairing branch; test builds only')
    parser.add_argument('--app', type=Path, default=ROOT / 'out/rust-target/debug/conwu.exe')
    parser.add_argument('--raw-app', type=Path, default=ROOT / 'out/rust-target/release/conwu-raw.exe')
    parser.add_argument('--linux-app', default=WSL_ROOT + '/out/rust-target-linux/debug/conwu')
    parser.add_argument('--public-fixture', action='store_true', help='Temporary documentation-address aliases on the owned WSL virtual link')
    parser.add_argument('--wsl-mtu', type=int, choices=[1500], help='Temporarily set the owned WSL test path to standard Ethernet MTU, then restore it')
    args = parser.parse_args()
    if args.managed:
        args.public_fixture = True
        args.modes = args.modes or ['faketcp']
        if any(mode != 'faketcp' for mode in args.modes):
            raise ValueError('The forced managed SLF1/SLN1 gate applies to FakeTCP')
    if os.name != 'nt':
        raise RuntimeError('Run this gate on Windows with the ArchLinux WSL distribution')
    from live_session import require_idle
    require_idle()
    if args.managed or args.assisted:
        for command in ([str(args.app), 'build-info'], ['wsl', '-d', 'ArchLinux', '-u', 'root', '--', args.linux_app, 'build-info']):
            if not json.loads(subprocess.check_output(command, text=True))['labApi']:
                raise ValueError('Forced coverage requires explicit lab-api builds on both sides')
    token = uuid.uuid4().hex[:8]
    folder = ROOT / 'out/lab' / ('cross-' + token)
    folder.mkdir(parents=True)
    linux_folder = WSL_ROOT + '/out/lab/' + folder.name
    components = folder / 'components'
    components.mkdir()
    candidates = {
        'conwu-raw.exe': args.raw_app,
        'conwu-phantun.exe': ROOT / 'out/rust-target/release/conwu-phantun.exe',
        'udp2raw-native.exe': ROOT / 'out/native/udp2raw-native.exe',
        'wintun.dll': args.dependency_root / 'wintun/bin/amd64/wintun.dll',
        'WinDivert.dll': args.dependency_root / 'WinDivert-2.2.2-A/x64/WinDivert.dll',
        'WinDivert64.sys': args.dependency_root / 'WinDivert-2.2.2-A/x64/WinDivert64.sys',
        'xdpapi.dll': args.dependency_root / 'xdp-1.4.0/unpacked/runtime/native/xdpapi.dll',
    }
    modes = args.modes or ['tcp', 'https', 'phantun', 'mimic', 'tcpraw', 'faketcp']
    for name, source in candidates.items():
        if name=='conwu-raw.exe' and not any(m in ('mimic','tcpraw') for m in modes): continue
        if name=='conwu-phantun.exe' and 'phantun' not in modes: continue
        if name=='udp2raw-native.exe' and 'faketcp' not in modes: continue
        if name=='xdpapi.dll' and os.environ.get('CONWU_MIMIC_IO')!='xdp': continue
        if source.is_symlink() or not source.is_file():
            raise ValueError('Missing/linked component: ' + str(source))
        shutil.copyfile(source, components / name)
    addresses = json.loads(subprocess.check_output(['wsl', '-d', 'ArchLinux', '-u', 'root', '--',
        'ip', '-j', '-4', 'addr', 'show', 'eth0'], text=True))
    linux_ip = addresses[0]['addr_info'][0]['local']
    ipaddress.IPv4Address(linux_ip)
    linux_primary = linux_ip
    links = json.loads(subprocess.check_output(['wsl', '-d', 'ArchLinux', '-u', 'root', '--',
        'ip', '-j', 'link', 'show', 'eth0'], text=True))
    original_mtu = links[0]['mtu']
    if original_mtu < 1404 and not args.wsl_mtu:
        raise ValueError('WSL outer MTU is below the existing 1280-byte overlay plus carrier overhead; use --wsl-mtu 1500 for this controlled Ethernet fixture')
    executable = folder / 'conwu-lab.exe'
    shutil.copyfile(args.app, executable)
    linux_environment = []
    if args.managed:
        linux_environment.append('CONWU_LAB_FORCE_MANAGED=1')
    commands = [
        [str(executable), 'run', '--data', str(folder / 'windows'), '--components', str(components), '--no-open', '--no-tray'],
        ['wsl', '-d', 'ArchLinux', '-u', 'root', '--', 'env', *linux_environment, args.linux_app, 'run',
         '--data', linux_folder + '/linux', '--components', WSL_ROOT + '/out/rust-components-linux', '--no-open', '--no-tray'],
    ]
    processes = [None, None]
    logs = []
    rules = []
    results = []
    fixture = None

    def setup_fixture():
        # Match the public-address admission rules without weakening product
        # checks or sending probes to the Internet. These addresses route only
        # across the existing WSL virtual link and are removed in finally.
        source, target = '192.0.2.66', '192.0.2.65'
        existing = json.loads(subprocess.check_output(['wsl', '-d', 'ArchLinux', '-u', 'root', '--', 'ip', '-j', '-4', 'address'], text=True))
        if any(a.get('local') in (source, target) for row in existing for a in row.get('addr_info', [])):
            raise ValueError('Documentation fixture addresses are already in use')
        routes = json.loads(subprocess.check_output(['wsl', '-d', 'ArchLinux', '-u', 'root', '--', 'ip', '-j', '-4', 'route', 'show', source + '/32'], text=True))
        if routes:
            raise ValueError('Documentation fixture route is already in use')
        script = """
$ErrorActionPreference='Stop'
$entry=Find-NetRoute -RemoteIPAddress 'PRIMARY' | Where-Object { $_.PSObject.Properties['IPAddress'] } | Select-Object -First 1
$adapter=Get-NetAdapter -IncludeHidden | Where-Object { $_.ifIndex -eq $entry.InterfaceIndex }
if(-not $entry -or $adapter.InterfaceDescription -notlike '*Hyper-V*Virtual Ethernet*'){throw 'Fixture must use the WSL Hyper-V link'}
$primary=Get-NetIPAddress -InterfaceIndex $entry.InterfaceIndex -IPAddress $entry.IPAddress
if(Get-NetIPAddress -IPAddress '192.0.2.66' -ErrorAction SilentlyContinue){throw 'Fixture source exists'}
if(Get-NetRoute -DestinationPrefix '192.0.2.65/32' -ErrorAction SilentlyContinue){throw 'Fixture route exists'}
$created=$false
try {
 $null=New-NetIPAddress -InterfaceIndex $entry.InterfaceIndex -IPAddress '192.0.2.66' -PrefixLength 32 -SkipAsSource $false -PolicyStore ActiveStore
 $created=$true
 $null=New-NetRoute -InterfaceIndex $entry.InterfaceIndex -DestinationPrefix '192.0.2.65/32' -NextHop 'PRIMARY' -RouteMetric 1 -PolicyStore ActiveStore
 $null=Set-NetIPAddress -InterfaceIndex $entry.InterfaceIndex -IPAddress $entry.IPAddress -SkipAsSource $true
 [ordered]@{index=$entry.InterfaceIndex;windowsPrimary=$entry.IPAddress;windowsSkip=$primary.SkipAsSource}|ConvertTo-Json -Compress
} catch {
 $null=Set-NetIPAddress -InterfaceIndex $entry.InterfaceIndex -IPAddress $entry.IPAddress -SkipAsSource $primary.SkipAsSource
 if($created){Get-NetRoute -InterfaceIndex $entry.InterfaceIndex -DestinationPrefix '192.0.2.65/32' -ErrorAction SilentlyContinue|Remove-NetRoute -Confirm:$false;Get-NetIPAddress -InterfaceIndex $entry.InterfaceIndex -IPAddress '192.0.2.66' -ErrorAction SilentlyContinue|Remove-NetIPAddress -Confirm:$false}
 throw
}
""".replace('PRIMARY', linux_primary)
        value = json.loads(ps(script))
        ipaddress.IPv4Address(value['windowsPrimary'])
        return value

    def clear_fixture(value):
        index = int(value['index'])
        primary = str(ipaddress.IPv4Address(value['windowsPrimary']))
        skip = '$true' if value['windowsSkip'] else '$false'
        try:
            ps("$null=Set-NetIPAddress -InterfaceIndex " + str(index) + " -IPAddress '" + primary + "' -SkipAsSource " + skip + "\nGet-NetRoute -InterfaceIndex " + str(index) + " -DestinationPrefix '192.0.2.65/32' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false\nGet-NetIPAddress -InterfaceIndex " + str(index) + " -IPAddress '192.0.2.66' -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false")
        finally:
            subprocess.run(['wsl', '-d', 'ArchLinux', '-u', 'root', '--', 'ip', '-4', 'route', 'del', '192.0.2.66/32', 'dev', 'eth0'], capture_output=True)
            subprocess.run(['wsl', '-d', 'ArchLinux', '-u', 'root', '--', 'ip', '-4', 'address', 'del', '192.0.2.65/32', 'dev', 'eth0'], capture_output=True)

    def start(index):
        log = (folder / ('process-' + str(index) + '.log')).open('ab')
        logs.append(log)
        environment = os.environ.copy()
        if args.managed:
            environment['CONWU_LAB_FORCE_MANAGED'] = '1'
        if args.assisted and index == 0:
            environment['CONWU_LAB_FORCE_ASSISTANCE'] = '1'
        processes[index] = subprocess.Popen(commands[index], stdout=log, stderr=log, env=environment,
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

    def stop(index, cleanup=False):
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
                if not cleanup:
                    raise
        if not cleanup and process.returncode:
            raise RuntimeError('Backend did not shut down cleanly on side ' + str(index))
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
        if args.public_fixture:
            fixture = setup_fixture()
            subprocess.run(['wsl', '-d', 'ArchLinux', '-u', 'root', '--', 'ip', '-4', 'address', 'add', '192.0.2.65/32', 'dev', 'eth0'], check=True, capture_output=True)
            subprocess.run(['wsl', '-d', 'ArchLinux', '-u', 'root', '--', 'ip', '-4', 'route', 'add', '192.0.2.66/32', 'via', fixture['windowsPrimary'], 'dev', 'eth0', 'src', '192.0.2.65'], check=True, capture_output=True)
            linux_ip = '192.0.2.65'
        if args.wsl_mtu:
            subprocess.run(['wsl', '-d', 'ArchLinux', '-u', 'root', '--', 'ip', 'link', 'set',
                'eth0', 'mtu', str(args.wsl_mtu)], check=True, capture_output=True)
        start(0)
        start(1)
        if args.assisted or args.managed:
            rpc(1, {'method': 'save-settings', 'settingsBatch': {'device': {'settings': {'coordinator': {'enabled': True, 'listenUrl': 'https://0.0.0.0:1145'}}}}})
            pin = rpc(1, {'method': '_status'})['status']['coordinator']['certificatePin']
        for offset, mode in enumerate(args.modes or ['tcp', 'https', 'phantun', 'mimic', 'tcpraw', 'faketcp']):
            begin = time.monotonic()
            listen = 48900 + offset * 10
            settings = rpc(1, {'method': '_status'})['status']['networkDefaults']
            settings.update(pathSelection=mode + '-only', connectionSource='existing', discoveryMode='existing',
                            listenPort=listen, sourcePort=listen + 1,
                            existingEntries=[{'peerSlot': 0, 'source': linux_ip + ':' + str(listen)}])
            if args.assisted or args.managed:
                settings.update(connectionSource='custom', discoveryMode='coordinator', service='https://' + linux_ip + ':1145', certificatePin=pin, existingEntries=[], tcpStun=[linux_ip + ':1145'], disableGatewayMapping=True)
            config = rpc(1, {'method': 'configuration', 'configuration': {
                'action': 'save', 'id': '', 'name': 'Cross ' + mode, 'expectedRevision': 0, 'settings': settings}})
            created = rpc(1, {'method': 'network', 'network': {
                'action': 'create-direct', 'name': 'Cross ' + mode, 'configurationId': config['configurationId'], 'mode': mode}})
            host = created['status']['selectedNetworkId']
            if args.assisted or args.managed:
                wait('same-source candidate ' + mode, lambda: row(1, host)['entryPreparation']['state'] == 'Ready', timeout=60)
            invitation = rpc(1, {'method': 'network', 'networkId': host, 'network': {'action': 'invite-compact', 'expectedNetwork': host}})
            code = next(n['status']['pairing']['code'] for n in invitation['status']['networks'] if n['id'] == host)
            joined = rpc(0, {'method': 'network', 'network': {'action': 'join-compact', 'code': code, 'name': 'Cross Windows'}})
            guest = joined['status']['selectedNetworkId']
            wait('SAS ' + mode, lambda: len(row(1, host)['pairing'].get('verification', '')) == 6)
            pending = row(1, host)['pairing']
            rpc(1, {'method': 'network', 'networkId': host, 'network': {
                'action': 'approve', 'verification': pending['verification'], 'candidate': pending['candidate']}})
            wait('direct ' + mode, lambda: row(1, host)['directPeers'] == 1 and row(0, guest)['directPeers'] == 1,
                 timeout=120 if args.managed else 45)
            if args.managed:
                wait('authenticated SLN1 selection ' + mode, lambda: (row(1, host).get('managedTraversal') or {}).get('selected') and (row(0, guest).get('managedTraversal') or {}).get('selected'))
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
                # All previous networks remain enabled: Windows may perform a
                # bounded 30s class-settle plus one native-create retry for
                # each adapter. Account for every saved adapter in this gate.
                wait('restart restore ' + mode, lambda: all(n['status']['directPeers'] == 1
                    for n in rpc(0, {'method': '_status'})['status']['networks']),
                    timeout=max(150, (offset + 1) * 90))
                ping(0, h['virtualIp'])
            result = {'mode': mode, 'windowsAdapter': g['adapter'], 'linuxAdapter': h['adapter'],
                      'managed': args.managed, 'assisted': args.assisted,
                      'pairing': True, 'bidirectionalTun': True, 'reconnect': True,
                      'restart': args.restart, 'seconds': round(time.monotonic() - begin, 2)}
            results.append(result)
            print(json.dumps(result), flush=True)
            prefix = 'managed-' if args.managed else 'assisted-' if args.assisted else ''
            (ROOT / ('out/' + prefix + 'windows-linux-lab-result.json')).write_text(json.dumps(results, indent=2), encoding='utf-8')
    except Exception:
        for index in range(2):
            try:
                state = rpc(index, {'method': '_status'})['status']
                (folder / ('failed-status-' + str(index) + '.private.json')).write_text(json.dumps(state), encoding='utf-8')
            except Exception:
                pass
        raise
    finally:
        try:
            for index in range(2):
                stop(index, cleanup=True)
            for rule in rules:
                ps("Get-NetFirewallRule -Name '" + rule + "' -ErrorAction SilentlyContinue | Remove-NetFirewallRule")
            for log in logs:
                log.close()
        finally:
            try:
                if fixture:
                    clear_fixture(fixture)
            finally:
                if args.wsl_mtu:
                    subprocess.run(['wsl', '-d', 'ArchLinux', '-u', 'root', '--', 'ip', 'link', 'set',
                        'eth0', 'mtu', str(original_mtu)], check=True, capture_output=True)


if __name__ == '__main__':
    main()
