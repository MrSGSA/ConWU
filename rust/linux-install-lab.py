"""Real systemd first-install, repair and failed-candidate rollback gate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent
UNIT = 'conwu-rust-experiment.service'
UNIT_FILE = Path('/run/systemd/system') / UNIT


def run(*args, check=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=320)
    if check and result.returncode:
        raise RuntimeError(result.stderr[-4000:] or 'Isolated install command failed')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app', required=True, type=Path)
    args = parser.parse_args()
    assert os.geteuid() == 0
    assert run('systemctl', 'show', UNIT, '--property=LoadState', '--value', check=False).stdout.strip() == 'not-found'
    assert not UNIT_FILE.exists()
    token = uuid.uuid4().hex
    source = Path('/var/cache/conwu-rust-build') / ('install-bundle-' + token)
    source.mkdir()
    app = source / 'conwu'
    run('strip', '--strip-debug', '-o', str(app), str(args.app))
    app.chmod(0o755)
    info = json.loads(run(str(app), 'build-info').stdout)
    assert not info['production'] and info['localInstall'] and not info['labApi']
    marker = dict(product=info['product'], version=info['version'], os='linux', arch='x86_64')
    (source / '.conwu-rust-package').write_text(json.dumps(marker))
    for before, after in [('install-linux.py', 'install.py'), ('install-linux.sh', 'install.sh')]:
        shutil.copyfile(ROOT / 'rust' / before, source / after)
    (source / 'install.sh').chmod(0o755)

    def hashes():
        entries = [hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.name + '\n'
                   for p in sorted(source.iterdir()) if p.is_file() and p.name != 'SHA256SUMS']
        (source / 'SHA256SUMS').write_text(''.join(entries))
    hashes()
    # The D:-hosted WSL VHD holds this fixture. Keep executable copies on its
    # native filesystem instead of measuring DrvFs 9P writeback delays.
    folder = Path('/var/cache/conwu-rust-build') / ('conwu-install-validation-' + token)
    data = folder / 'data'
    def install(check=True):
        return run('python3', str(source / 'install.py'), '--validation-root', str(folder), check=check)
    def status():
        return json.loads(run(str(folder / 'program/current/conwu'), '--data', str(data), 'status').stdout)
    def rpc(body):
        return json.loads(subprocess.run(['python3', str(ROOT / 'rust/lab-client.py'), str(data), '-'], input=json.dumps(body), capture_output=True, text=True, check=True, timeout=45).stdout)
    try:
        install()
        print(json.dumps(dict(firstInstall=True)), flush=True)
        settings = status()['networkDefaults']
        settings.update(pathSelection='tcp-only', connectionSource='existing', discoveryMode='existing', listenPort=27780, sourcePort=27781, pkarrPublish=False, existingEntries=[dict(peerSlot=0, source='192.0.2.253:27780')])
        config = rpc(dict(method='configuration', configuration=dict(action='save', id='', name='Install gate', expectedRevision=0, settings=settings)))
        rpc(dict(method='network', network=dict(action='create-direct', name='Install gate', configurationId=config['configurationId'])))
        state = status()
        network = state['networks'][0]
        baseline = (network['id'], network['status']['virtualIp'])
        install()
        restored = status()['networks'][0]
        assert (restored['id'], restored['status']['virtualIp']) == baseline and restored['status']['adapter']['ready']
        assert (data / 'update-rollback/settings/database.private.json').is_file()
        assert (folder / 'program/conwu-rust-previous/conwu').is_file()
        print(json.dumps(dict(repairPreservesNetwork=True, realTunReady=True, completePreviousSnapshot=True)), flush=True)
        # A test-only executable supplies the genuine build identity to the
        # installer's preflight but exits on service startup. No product build
        # accepts these experimental paths or embeds this fault executable.
        app.write_text('#!/bin/sh\nif [ "$1" = build-info ]; then\nexec ' + str(args.app) + ' build-info\nfi\nexit 42\n')
        app.chmod(0o755)
        hashes()
        failed = install(check=False)
        assert failed.returncode != 0, 'Fault candidate was incorrectly accepted'
        restored = status()['networks'][0]
        assert (restored['id'], restored['status']['virtualIp']) == baseline and restored['status']['adapter']['ready']
        assert (folder / 'program/current/conwu').read_bytes()[:4] == b'\x7fELF'
        # Exercise the same uninstall path while retaining the approved data.
        shutil.copyfile(ROOT / 'rust/install-linux.py', source / 'install.py')
        hashes()
        run('python3', str(source / 'install.py'), '--validation-root', str(folder), '--uninstall')
        assert (data / 'database.private.json').is_file() and not (folder / 'program/current').exists()
        evidence = dict(firstInstall=True, repairPreservesNetwork=True, realTunRestored=True, completePreviousSnapshot=True, failedCandidateRollback=True, uninstallRetainsData=True, productionUntouched=True)
        (ROOT / 'out/parity-linux-install-result.json').write_text(json.dumps(evidence, indent=2))
        print(json.dumps(evidence), flush=True)
    finally:
        run('systemctl', 'stop', UNIT, check=False)
        run('systemctl', 'reset-failed', UNIT, check=False)
        if UNIT_FILE.is_file() and str(folder / 'program') in UNIT_FILE.read_text():
            UNIT_FILE.unlink()
        run('systemctl', 'daemon-reload')


if __name__ == '__main__':
    main()
