"""Two Linux namespaces; real six-carrier packets, memory overlay adapters.

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
parser.add_argument('--app', type=Path, default=root / 'out/rust-target-linux/debug/conwu')
parser.add_argument('modes', nargs='*', choices=['tcp', 'https', 'phantun', 'mimic', 'tcpraw', 'faketcp'])
args = parser.parse_args()
real_tun, assisted, managed = args.tun, args.assisted, args.managed
modes = args.modes or (['tcp', 'https'] if args.ipv6 else ['tcp', 'https', 'phantun', 'mimic', 'tcpraw', 'faketcp'])
if args.ipv6 and (assisted or managed or any(mode not in ('tcp', 'https') for mode in modes)):
    raise ValueError('IPv6 currently covers direct TCP/HTTPS, without IPv4 assistance flags')
try:
    for name in names:
        run('ip', 'netns', 'add', name)
        created.append(name)
        run('ip', '-n', name, 'link', 'set', 'lo', 'up')
    run('ip', 'link', 'add', peers[0], 'type', 'veth', 'peer', 'name', peers[1])
    for index in range(2):
        run('ip', 'link', 'set', peers[index], 'netns', names[index])
        run('ip', '-n', names[index], 'addr', 'add', '192.0.2.' + str(index + 1) + '/24', 'dev', peers[index])
        if args.ipv6:
            run('ip', '-n', names[index], '-6', 'addr', 'add', 'fd42:7465:7374::' + str(index + 1) + '/64', 'dev', peers[index], 'nodad')
        run('ip', '-n', names[index], 'link', 'set', peers[index], 'up')
        log = (directory / ('process-' + str(index) + '.log')).open('wb')
        command = ['ip', 'netns', 'exec', names[index], str(args.app), 'run', '--data', str(directory / str(index)), '--components', str(root / 'out/rust-components-linux'), '--no-open', '--no-tray']
        if not real_tun: command.append('--memory')
        environment = os.environ.copy()
        if assisted and index == 1:
            environment['CONWU_LAB_FORCE_ASSISTANCE'] = '1'
        if managed:
            environment['CONWU_LAB_FORCE_MANAGED'] = '1'
        process = subprocess.Popen(command, stdout=log, stderr=log, env=environment)
        processes.append(process)
        wait('backend start', lambda i=index: (directory / str(i) / 'panel.private.json').exists())
    if assisted:
        rpc(0, {'method': 'save-settings', 'settingsBatch': {'device': {'settings': {'coordinator': {'enabled': True, 'listenUrl': 'https://0.0.0.0:1145'}}}}})
        pin = rpc(0, {'method': '_status'})['status']['coordinator']['certificatePin']
    for offset, mode in enumerate(modes):
        begin = time.monotonic()
        listen = 48000 + offset * 10
        settings = rpc(0, {'method': '_status'})['status']['networkDefaults']
        settings.update(pathSelection=mode + '-only', connectionSource='existing', discoveryMode='existing', listenPort=listen, sourcePort=listen + 1, existingEntries=[{'peerSlot': 0, 'source': '192.0.2.1:' + str(listen)}])
        if args.ipv6:
            settings['existingEntries'] = [{'peerSlot': 0, 'source': '[fd42:7465:7374::1]:' + str(listen)}]
        if assisted:
            settings.update(connectionSource='custom', discoveryMode='coordinator', service='https://192.0.2.1:1145', certificatePin=pin, existingEntries=[], tcpStun=['192.0.2.1:1145'], disableGatewayMapping=True)
        config = rpc(0, {'method': 'configuration', 'configuration': {'action': 'save', 'id': '', 'name': mode, 'expectedRevision': 0, 'settings': settings}})
        created_network = rpc(0, {'method': 'network', 'network': {'action': 'create-direct', 'name': mode, 'configurationId': config['configurationId'], 'mode': mode}})
        host = created_network['status']['selectedNetworkId']
        if assisted:
            wait('retained source candidate ' + mode, lambda: next(n['status'] for n in rpc(0, {'method': '_status'})['status']['networks'] if n['id'] == host)['entryPreparation']['state'] == 'Ready')
        invitation = rpc(0, {'method': 'network', 'networkId': host, 'network': {'action': 'invite-compact', 'expectedNetwork': host}})
        host_pair = next(n for n in invitation['status']['networks'] if n['id'] == host)['status']['pairing']
        if args.ipv6:
            assert len(host_pair['code'].replace('-', '')) == 36
        joined = rpc(1, {'method': 'network', 'network': {'action': 'join-compact', 'code': host_pair['code'], 'name': mode}})
        guest = joined['status']['selectedNetworkId']
        def pairing():
            status = rpc(0, {'method': '_status'})['status']
            return next(n for n in status['networks'] if n['id'] == host)['status']['pairing']
        wait('SAS ' + mode, lambda: len(pairing().get('verification', '')) == 6)
        pending = pairing()
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
                assert len(received) == 1 and len(base64.b64decode(received[0])) == 1028
        results.append({'mode': mode, 'assisted': assisted, 'managed': managed, 'outerIpv6': args.ipv6, 'pairingAndBidirectionalData': True, 'adapter':'Linux.TUN' if real_tun else 'Memory', 'seconds': round(time.monotonic() - begin, 2)})
        print(json.dumps(results[-1]), flush=True)
    result_name = ('ipv6-' if args.ipv6 else 'managed-' if managed else 'assisted-' if assisted else '') + ('tun-lab-result.json' if real_tun else 'native-lab-result.json')
    (root / 'out' / result_name).write_text(json.dumps(results, indent=2))
finally:
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
