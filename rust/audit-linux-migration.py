"""Audit a read-only Linux migration without printing credentials."""
import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('legacy', type=Path)
parser.add_argument('rust', type=Path)
args = parser.parse_args()

def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))

old = read(args.legacy / 'profile.json')
new = read(args.rust / 'database.private.json')
assert old['NodeSigningPrivate'] == new['nodePrivate'], 'Device identity changed'
assert old['DeviceName'] == new['deviceName'], 'Device name changed'
assert old['AutoStart'] == new['deviceSettings']['autoStart'], 'Startup preference changed'
assert old['Coordinator']['Enabled'] == new['deviceSettings']['coordinator']['enabled']
assert old['Coordinator']['TrustCloudflare'] == new['deviceSettings']['coordinator']['trustCloudflare']
registry = args.legacy / 'coordination/mesh-networks.json'
if registry.is_file():
    assert read(registry) == read(args.rust / 'coordinator.json'), 'Coordinator identities or high-water marks changed'
remote = args.legacy / 'remote-admin.json'
if remote.is_file():
    assert read(remote) == read(args.rust / 'remote-admin.json'), 'Remote administration settings changed'
networks = 0
for folder in (args.legacy / 'networks').glob('*'):
    info = read(folder / 'network-info.json')
    if info.get('Removed') or info.get('PendingEnrollment'):
        continue
    before = read(folder / 'profile.json')
    if not before.get('Mesh'):
        continue
    after = next(n for n in new['networks'] if n['id'] == info['Id'])
    assert before['Mesh'] == after['profile'], 'Network profile changed'
    assert before['PkarrSeed'] == after['pkarrSeed']
    assert before['PkarrSequence'] == after['pkarrSequence']
    assert before['Enabled'] == after['enabled']
    assert before['ConnectionPaused'] == after['paused']
    networks += 1
assert len(new['networks']) == networks, 'Network collection changed'
print(json.dumps(dict(deviceIdentityPreserved=True, coordinatorRegistryPreserved=True,
    coordinatorPreferencesPreserved=True, remoteAdministrationPreserved=True,
    networks=networks, started=False), indent=2))
