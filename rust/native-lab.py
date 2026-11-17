"""Isolated Linux namespaces; real six-carrier packets, memory overlay adapters.

All interfaces and firewall changes are confined to these owned namespaces.
The optional lab API must be enabled for this executable only.
"""
import argparse
import base64
import json
import os
import socket
import struct
import subprocess
import sys
import time
import uuid
from pathlib import Path

root = Path(__file__).resolve().parent.parent
token = uuid.uuid4().hex[:8]
names = ['cwru-a-' + token, 'cwru-b-' + token]
peers = ['cwa' + token, 'cwb' + token]
directory = root / 'out/lab' / ('native-' + token)
directory.mkdir(parents=True)
processes = []
created = []
def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)
def rpc(index, body):
    result = subprocess.run(['ip', 'netns', 'exec', names[index], 'python3', str(root / 'rust/lab-client.py'), str(directory / str(index)), json.dumps(body)], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"RPC {body.get('method')}: {result.stderr[-2000:]}")
    return json.loads(result.stdout)
def wait(label, condition):
    # Allow the bounded first-enrolment delivery and the carrier's retry round
    # while compiler/installer verification is running on the same lab host.
    until = time.monotonic() + 60
    while time.monotonic() < until:
        if condition():
            return
        time.sleep(0.25)
    raise TimeoutError(label)
def packet(source, target, marker):
    payload = bytes([marker]) * 1000
    udp = struct.pack('!HHHH', 47998, 47998, len(payload) + 8, 0) + payload
    ip = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0, socket.inet_aton(source), socket.inet_aton(target)))
    checksum = sum(struct.unpack('!10H', ip))
    while checksum >> 16:
        checksum = (checksum & 65535) + (checksum >> 16)
    ip[10:12] = struct.pack('!H', ~checksum & 65535)
    return bytes(ip) + udp
results = []
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--tun', action='store_true')
parser.add_argument('--assisted', action='store_true')
parser.add_argument('--managed', action='store_true')
parser.add_argument('--ipv6', action='store_true')
parser.add_argument('--nat', action='store_true', help='Two independent SNAT routers with conntrack-only inbound traffic; requires --assisted')
parser.add_argument('--app', type=Path, default=root / 'out/rust-target-linux/debug/conwu')
parser.add_argument('--components', type=Path, default=root / 'out/rust-components-linux')
parser.add_argument('modes', nargs='*', choices=['tcp', 'https', 'phantun', 'mimic', 'tcpraw', 'faketcp'])
args = parser.parse_args()
real_tun, assisted, managed = args.tun, args.assisted, args.managed
modes = args.modes or (['tcp', 'https'] if args.ipv6 else ['tcp', 'https', 'phantun', 'mimic', 'tcpraw', 'faketcp'])
if args.ipv6 and (assisted or managed or any(mode not in ('tcp', 'https') for mode in modes)):
    raise ValueError('IPv6 currently covers direct TCP/HTTPS, without IPv4 assistance flags')
if args.nat and (not assisted or managed or args.ipv6):
    raise ValueError('--nat requires IPv4 --assisted without --managed')
if args.nat:
    names.extend(['cwru-c-' + token, 'cwru-ra-' + token, 'cwru-rb-' + token])
coordinator_index = 2 if args.nat else 0
coordinator_address = '192.0.2.2' if args.nat else '192.0.2.1'
nat_links = []
launches = [0, 0, 0]
def launch(index):
    suffix = f'-restart-{launches[index]}' if launches[index] else ''
    if launches[index]:
        # Web sessions belong to the old backend process, not its saved member
        # identity. A restarted fixture must obtain a fresh local session.
        (directory / str(index) / 'lab-session.private.json').unlink(missing_ok=True)
    launches[index] += 1
    command = ['ip', 'netns', 'exec', names[index], str(args.app), 'run', '--data', str(directory / str(index)), '--components', str(args.components), '--no-open', '--no-tray']
    if not real_tun:
        command.append('--memory')
    environment = os.environ.copy()
    environment.setdefault('RUST_LOG', 'conwu=debug')
    if assisted and index == 1:
        environment['CONWU_LAB_FORCE_ASSISTANCE'] = '1'
    if managed:
        environment['CONWU_LAB_FORCE_MANAGED'] = '1'
    with (directory / f'process-{index}{suffix}.log').open('wb') as log:
        return subprocess.Popen(command, stdout=log, stderr=log, env=environment)
def backend_ready(index):
    try:
        return bool(rpc(index, {'method': '_status'})['status'])
    except (RuntimeError, OSError, ValueError):
        return False
try:
    for name in names:
        run('ip', 'netns', 'add', name)
        created.append(name)
        run('ip', '-n', name, 'link', 'set', 'lo', 'up')
    if args.nat:
        # All forwarding and nft rules live in these five disposable namespaces.
        # Neither router has a DNAT/UPnP rule or a route to the real Internet.
        links = [(0, '10.220.1.2/30', 3, '10.220.1.1/30'),
                 (3, '192.0.2.1/30', 2, '192.0.2.2/30'),
                 (1, '10.220.2.2/30', 4, '10.220.2.1/30'),
                 (4, '198.51.100.1/30', 2, '198.51.100.2/30')]
        for number, (left, left_ip, right, right_ip) in enumerate(links):
            pair = [f'cn{token}{number}a', f'cn{token}{number}b']
            run('ip', 'link', 'add', pair[0], 'type', 'veth', 'peer', 'name', pair[1])
            nat_links.append(pair[0])
            for index, address, interface in [(left, left_ip, pair[0]), (right, right_ip, pair[1])]:
                run('ip', 'link', 'set', interface, 'netns', names[index])
                run('ip', '-n', names[index], 'addr', 'add', address, 'dev', interface)
                run('ip', '-n', names[index], 'link', 'set', interface, 'up')
        for index, gateway in [(0, '10.220.1.1'), (1, '10.220.2.1'), (3, '192.0.2.2'), (4, '198.51.100.2')]:
            run('ip', '-n', names[index], 'route', 'add', 'default', 'via', gateway)
        for index in [2, 3, 4]:
            run('ip', 'netns', 'exec', names[index], 'sysctl', '-q', '-w', 'net.ipv4.ip_forward=1')
        for index, subnet, public, lan, wan in [
            (3, '10.220.1.0/30', '192.0.2.1', f'cn{token}0b', f'cn{token}1a'),
            (4, '10.220.2.0/30', '198.51.100.1', f'cn{token}2b', f'cn{token}3a'),
        ]:
            rules = f'''table ip conwu_lab_nat {{
                chain source {{ type nat hook postrouting priority srcnat; policy accept;
                    ip saddr {subnet} oifname "{wan}" counter snat to {public}
                }}
                chain filtering {{ type filter hook forward priority filter; policy drop;
                    iifname "{lan}" oifname "{wan}" counter accept
                    iifname "{wan}" oifname "{lan}" ct state established,related counter accept
                    counter drop
                }}
                chain unsolicited {{ type filter hook input priority filter; policy drop;
                    iifname "lo" accept
                    ct state established,related counter accept
                    counter drop
                }}
            }}'''
            subprocess.run(['ip', 'netns', 'exec', names[index], 'nft', '-f', '-'], input=rules, text=True, check=True)
        (directory / 'topology.json').write_text(json.dumps({
            'scope': 'isolated Linux namespaces; synthetic documentation addresses',
            'mapping': 'Linux SNAT with default source-port allocation',
            'filtering': 'inbound forwarded traffic requires an existing conntrack tuple',
            'gatewayMappingDisabled': True, 'staticDnatRules': False, 'businessRelay': False,
            'coordinatorNamespace': names[2], 'clientNamespaces': names[:2], 'routerNamespaces': names[3:],
        }, indent=2))
    else:
        run('ip', 'link', 'add', peers[0], 'type', 'veth', 'peer', 'name', peers[1])
        for index in range(2):
            run('ip', 'link', 'set', peers[index], 'netns', names[index])
            run('ip', '-n', names[index], 'addr', 'add', '192.0.2.' + str(index + 1) + '/24', 'dev', peers[index])
            if args.ipv6:
                run('ip', '-n', names[index], '-6', 'addr', 'add', 'fd42:7465:7374::' + str(index + 1) + '/64', 'dev', peers[index], 'nodad')
            run('ip', '-n', names[index], 'link', 'set', peers[index], 'up')
    for index in range(3 if args.nat else 2):
        processes.append(launch(index))
        wait('backend start', lambda i=index: backend_ready(i))
    if assisted:
        rpc(coordinator_index, {'method': 'save-settings', 'settingsBatch': {'device': {'settings': {'coordinator': {'enabled': True, 'listenUrl': 'https://0.0.0.0:1145'}}}}})
        pin = rpc(coordinator_index, {'method': '_status'})['status']['coordinator']['certificatePin']
    for offset, mode in enumerate(modes):
        begin = time.monotonic()
        listen = 48000 + offset * 10
        settings = rpc(0, {'method': '_status'})['status']['networkDefaults']
        settings.update(pathSelection=mode + '-only', connectionSource='existing', discoveryMode='existing', listenPort=listen, sourcePort=listen + 1, existingEntries=[{'peerSlot': 0, 'source': '192.0.2.1:' + str(listen)}])
        if args.ipv6:
            settings['existingEntries'] = [{'peerSlot': 0, 'source': '[fd42:7465:7374::1]:' + str(listen)}]
        if assisted:
            settings.update(connectionSource='custom', discoveryMode='coordinator', service=f'https://{coordinator_address}:1145', certificatePin=pin, existingEntries=[], tcpStun=[f'{coordinator_address}:1145'], disableGatewayMapping=True)
        if args.nat:
            settings['entryRefreshSeconds'] = 60
        config = rpc(0, {'method': 'configuration', 'configuration': {'action': 'save', 'id': '', 'name': mode, 'expectedRevision': 0, 'settings': settings}})
        created_network = rpc(0, {'method': 'network', 'network': {'action': 'create-direct', 'name': mode, 'configurationId': config['configurationId'], 'mode': mode}})
        host = created_network['status']['selectedNetworkId']
        if assisted:
            wait('retained source candidate ' + mode, lambda: next(n['status'] for n in rpc(0, {'method': '_status'})['status']['networks'] if n['id'] == host)['entryPreparation']['state'] == 'Ready')
        if args.nat:
            endpoint = next(n['status'] for n in rpc(0, {'method': '_status'})['status']['networks'] if n['id'] == host)['entryPreparation']['endpoint']
            assert endpoint.startswith('192.0.2.1:'), 'host must publish the NAT observation'
            # A fresh source tuple at the reflector cannot enter the host's
            # retained STUN mapping; coordinated outbound traffic is required.
            check = 'import socket,sys; s=socket.socket(); s.settimeout(0.5); ip,port=sys.argv[1].rsplit(":",1); sys.exit(1 if s.connect_ex((ip,int(port)))==0 else 0)'
            subprocess.run(['ip', 'netns', 'exec', names[2], 'python3', '-c', check, endpoint], check=True)
        invitation = rpc(0, {'method': 'network', 'networkId': host, 'network': {'action': 'invite-compact', 'expectedNetwork': host}})
        host_pair = next(n for n in invitation['status']['networks'] if n['id'] == host)['status']['pairing']
        if args.ipv6:
            assert len(host_pair['code'].replace('-', '')) == 36
        joined = rpc(1, {'method': 'network', 'network': {'action': 'join-compact', 'code': host_pair['code'], 'name': mode}})
        guest = joined['status']['selectedNetworkId']
        def pairing():
            status = rpc(0, {'method': '_status'})['status']
            return next(n for n in status['networks'] if n['id'] == host)['status']['pairing']
        def sas_ready():
            status = rpc(1, {'method': '_status'})['status']
            guest_pair = next(n['status']['pairing'] for n in status['networks'] if n['id'] == guest)
            if guest_pair.get('error'):
                raise RuntimeError(f"{mode} pairing failed: {guest_pair['error']}")
            return len(pairing().get('verification', '')) == 6
        wait('SAS ' + mode, sas_ready)
        wait('matching guest SAS ' + mode, lambda: any(
            n['id'] == guest and n['status']['pairing'].get('verification') == pairing()['verification']
            for n in rpc(1, {'method': '_status'})['status']['networks']))
        pending = pairing()
        guest_status = rpc(1, {'method': '_status'})['status']
        guest_pairing = next(n['status']['pairing'] for n in guest_status['networks'] if n['id'] == guest)
        assert pending['verification'] == guest_pairing['verification'], 'both participants must verify the same SAS'
        assert not next(n['status']['directPeers'] for n in guest_status['networks'] if n['id'] == guest), 'coordinator hints must not grant membership'
        rpc(0, {'method': 'network', 'networkId': host, 'network': {'action': 'approve', 'verification': pending['verification'], 'candidate': pending['candidate']}})
        def row(index, identity):
            return next(n['status'] for n in rpc(index, {'method': '_status'})['status']['networks'] if n['id'] == identity)
        wait('direct path ' + mode, lambda: row(0, host)['directPeers'] == 1 and row(1, guest)['directPeers'] == 1)
        if managed:
            wait('authenticated SLN1 selection ' + mode, lambda: (row(0, host).get('managedTraversal') or {}).get('selected') and (row(1, guest).get('managedTraversal') or {}).get('selected'))
        h, g = row(0, host), row(1, guest)
        if real_tun:
            for index, target in [(0, g['virtualIp']), (1, h['virtualIp'])]:
                run('ip', 'netns', 'exec', names[index], 'ping', '-n', '-c', '3', '-W', '2', target)
        else:
            for index, identity, source, target in [(0, host, h['virtualIp'], g['virtualIp']), (1, guest, g['virtualIp'], h['virtualIp'])]:
                rpc(index, {'method': 'lab-inject', 'networkId': identity, 'packet': base64.b64encode(packet(source, target, index + 1)).decode()})
            wait('encrypted packets ' + mode, lambda: row(0, host)['peers'][0]['receivedBytes'] >= 1028 and row(1, guest)['peers'][0]['receivedBytes'] >= 1028)
            for index, identity in [(0, host), (1, guest)]:
                received = rpc(index, {'method': 'lab-read', 'networkId': identity})['operation']['result']['packets']
                expected = packet(g['virtualIp'], h['virtualIp'], 2) if index == 0 else packet(h['virtualIp'], g['virtualIp'], 1)
                assert len(received) == 1 and base64.b64decode(received[0]) == expected
        if args.nat:
            restart_began = time.monotonic()
            rpc(1, {'method': '_stop'})
            processes[1].wait(timeout=18)
            processes[1] = launch(1)
            wait('guest backend restart ' + mode, lambda: backend_ready(1))
            wait('saved-member NAT reconnection ' + mode, lambda: row(0, host)['directPeers'] == 1 and row(1, guest)['directPeers'] == 1)
            restart_seconds = round(time.monotonic() - restart_began, 2)
            if not real_tun:
                before = [row(0, host)['peers'][0]['receivedBytes'], row(1, guest)['peers'][0]['receivedBytes']]
                for index, identity, source, target in [(0, host, h['virtualIp'], g['virtualIp']), (1, guest, g['virtualIp'], h['virtualIp'])]:
                    rpc(index, {'method': 'lab-inject', 'networkId': identity, 'packet': base64.b64encode(packet(source, target, index + 11)).decode()})
                wait('restarted encrypted packets ' + mode, lambda: row(0, host)['peers'][0]['receivedBytes'] >= before[0] + 1028 and row(1, guest)['peers'][0]['receivedBytes'] >= before[1] + 1028)
                for index, identity in [(0, host), (1, guest)]:
                    received = rpc(index, {'method': 'lab-read', 'networkId': identity})['operation']['result']['packets']
                    expected = packet(g['virtualIp'], h['virtualIp'], 12) if index == 0 else packet(h['virtualIp'], g['virtualIp'], 11)
                    assert len(received) == 1 and base64.b64decode(received[0]) == expected
            else:
                for index, target in [(0, g['virtualIp']), (1, h['virtualIp'])]:
                    run('ip', 'netns', 'exec', names[index], 'ping', '-n', '-c', '3', '-W', '2', target)
        results.append({'mode': mode, 'assisted': assisted, 'managed': managed, 'outerIpv6': args.ipv6, 'dualSnatWithConntrackFiltering': args.nat, 'unsolicitedHostEntryBlocked': args.nat, 'guestRestartRecovery': args.nat, 'pairingAndBidirectionalData': True, 'adapter':'Linux.TUN' if real_tun else 'Memory', 'seconds': round(time.monotonic() - begin, 2)})
        if args.nat:
            results[-1]['guestRestartSeconds'] = restart_seconds
        print(json.dumps(results[-1]), flush=True)
    result_name = ('nat-' if args.nat else '') + ('ipv6-' if args.ipv6 else 'managed-' if managed else 'assisted-' if assisted else '') + ('tun-lab-result.json' if real_tun else 'native-lab-result.json')
    (root / 'out' / result_name).write_text(json.dumps(results, indent=2))
finally:
    for index in range(len(processes)):
        try:
            (directory / f'final-status-{index}.private.json').write_text(json.dumps(rpc(index, {'method': '_status'}), ensure_ascii=False, indent=2))
        except (RuntimeError, OSError, ValueError):
            pass
    if args.nat:
        (directory / 'completed-modes.json').write_text(json.dumps(results, indent=2))
        for index in [3, 4]:
            if names[index] in created:
                evidence = subprocess.run(['ip', 'netns', 'exec', names[index], 'nft', '-j', 'list', 'ruleset'], capture_output=True, text=True)
                (directory / f'router-{index}.json').write_text(evidence.stdout)
    for index, process in enumerate(processes):
        try:
            rpc(index, {'method': '_stop'})
            process.wait(timeout=18)
        except Exception:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    for name in reversed(created):
        subprocess.run(['ip', 'netns', 'delete', name], check=False)
    for interface in nat_links:
        subprocess.run(['ip', 'link', 'delete', interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
