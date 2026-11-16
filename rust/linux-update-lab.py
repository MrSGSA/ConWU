"""Isolated real-systemd update/rollback gate, including KillMode=control-group.

Requires root and a free experimental unit name. Never uses streamlink.service
or production data. Its transient unit file is removed in finally.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tarfile
import time
import uuid

ROOT=Path(__file__).resolve().parent.parent
UNIT='conwu-rust-experiment.service'
unit_file=Path('/run/systemd/system')/UNIT


def systemctl(*args,check=True):
    return subprocess.run(['systemctl',*args],capture_output=True,text=True,check=check)


def wait(label,test,timeout=150):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        try:
            value=test()
            if value: return value
        except (OSError,ValueError,RuntimeError,subprocess.SubprocessError): pass
        time.sleep(.3)
    raise TimeoutError(label)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app',type=Path,default=ROOT/'out/rust-target-linux/debug/conwu')
    args=parser.parse_args()
    assert os.geteuid()==0
    assert systemctl('show',UNIT,'--property=LoadState','--value',check=False).stdout.strip()=='not-found','Experimental unit name is already in use'
    assert not unit_file.exists()
    folder=ROOT/'out/lab'/('systemd-update-'+uuid.uuid4().hex[:8])
    program=folder/'current'
    program.mkdir(parents=True)
    exe=program/'conwu'
    shutil.copyfile(args.app,exe)
    exe.chmod(0o755)
    subprocess.run(['strip','--strip-debug',str(exe)],check=True)
    info=json.loads(subprocess.check_output([str(exe),'build-info'],text=True))
    assert info['localInstall'] and not info['production'] and not info['labApi']
    marker=dict(product=info['product'],version=info['version'],os='linux',arch='x86_64',experimental=True)
    (program/'.conwu-rust-package').write_text(json.dumps(marker))
    data=folder/'data'
    def quote(path): return '"'+str(path).replace('\\','\\\\').replace('"','\\"')+'"'
    unit='[Unit]\nDescription=ConWU isolated update gate\nStartLimitIntervalSec=20\nStartLimitBurst=3\n[Service]\nExecStart='+quote(exe)+' run --data '+quote(data)+' --components '+quote(ROOT/'out/rust-components-linux')+' --no-open --no-tray\nRestart=on-failure\nRestartSec=0.5\nKillMode=control-group\n'
    unit_file.write_text(unit)
    systemctl('daemon-reload')
    session_pid=None
    def rpc(body):
        nonlocal session_pid
        pid=json.loads((data/'panel.private.json').read_text())['pid']
        if pid!=session_pid:
            session=data/'lab-session.private.json'
            if session.is_file(): session.unlink()
            session_pid=pid
        result=subprocess.run(['python3',str(ROOT/'rust/lab-client.py'),str(data),'-'],input=json.dumps(body),capture_output=True,text=True,timeout=45)
        if result.returncode: raise RuntimeError('Local control request failed')
        return json.loads(result.stdout)
    def status(): return rpc({'method':'_status'})['status']
    def ready():
        state=status()
        return state if all(n['status']['adapter']['ready'] for n in state['networks']) and (state['deviceSettings']['coordinator']['enabled'] is not True or state['coordinator']['running']) else None
    def package(path,bad=False):
        with tarfile.open(path,'w:gz') as archive:
            for name in ('.conwu-rust-package','conwu'):
                payload=(program/name).read_bytes()
                if name=='conwu' and bad: payload=b'#!/bin/sh\nexit 42\n'
                item=tarfile.TarInfo(name)
                item.mode=0o755 if name=='conwu' else 0o644
                item.size=len(payload)
                archive.addfile(item,io.BytesIO(payload))
    try:
        systemctl('start',UNIT)
        wait('initial backend',ready)
        settings=status()['networkDefaults']
        settings.update(pathSelection='tcp-only',connectionSource='existing',discoveryMode='existing',listenPort=27680,sourcePort=27681,pkarrPublish=False,
            existingEntries=[dict(peerSlot=0,source='192.0.2.253:27680')])
        config=rpc(dict(method='configuration',configuration=dict(action='save',id='',name='Systemd update gate',expectedRevision=0,settings=settings)))
        rpc(dict(method='network',network=dict(action='create-direct',name='Systemd update gate',configurationId=config['configurationId'])))
        rpc(dict(method='save-settings',settingsBatch=dict(device=dict(settings=dict(coordinator=dict(enabled=True,listenUrl='https://127.0.0.1:27682/'))))))
        baseline=wait('network and coordination ready',ready)
        network=baseline['networks'][0]
        identity=(network['id'],network['status']['virtualIp'])
        good=folder/'valid-update.tar.gz'
        package(good)
        results=[]
        for bad in (False,True):
            candidate=folder/'failed-update.tar.gz' if bad else good
            if bad: package(candidate,True)
            systemctl('stop',UNIT)
            updates=data/'updates'
            updates.mkdir(exist_ok=True)
            target=updates/candidate.name
            shutil.copyfile(candidate,target)
            ticket=secrets.token_hex(32)
            (data/'update-ready.private.json').write_text(json.dumps(dict(package=str(target),sha256=hashlib.sha256(target.read_bytes()).hexdigest(),version=info['version'],ticket=ticket)))
            for name in ('last-update.json','panel.private.json','lab-session.private.json'):
                path=data/name
                if path.is_file(): path.unlink()
            if systemctl('show',UNIT,'--property=ActiveState','--value').stdout.strip()=='failed':
                systemctl('reset-failed',UNIT)
            systemctl('start',UNIT)
            wait('restart before update',ready)
            old_pid=systemctl('show',UNIT,'--property=MainPID','--value').stdout.strip()
            # lab-client drives the normal session/CSRF UI API. The command is
            # expected to lose its status poll once the service stops itself.
            try: rpc(dict(method='update-install',localUpdate=dict(ticket=ticket,version=info['version'])))
            except (RuntimeError,subprocess.TimeoutExpired): pass
            def finished():
                record=json.loads((data/'last-update.json').read_text())
                return record if record.get('state') in ('Installed','Error') else None
            record=wait('detached updater completion',finished,timeout=360)
            assert record['state']==('Error' if bad else 'Installed'),record.get('detail')
            restored=wait('restored real TUN and coordination',ready)
            row=restored['networks'][0]
            assert (row['id'],row['status']['virtualIp'])==identity
            assert systemctl('show',UNIT,'--property=MainPID','--value').stdout.strip()!=old_pid
            assert (data/'update-rollback/settings/database.private.json').is_file()
            assert (program/'conwu').read_bytes()[:4]==b'\x7fELF'
            results.append(dict(fault=bad,state=record['state'],detachedSystemdWorker=True,realTunRestored=True,coordinatorRestored=True,networkIdentityPreserved=True))
            print(json.dumps(results[-1]),flush=True)
        (ROOT/'out/parity-linux-update-result.json').write_text(json.dumps(results,indent=2))
    finally:
        systemctl('stop',UNIT,check=False)
        systemctl('reset-failed',UNIT,check=False)
        if unit_file.is_file() and str(exe) in unit_file.read_text(): unit_file.unlink()
        systemctl('daemon-reload')


if __name__=='__main__':
    main()
