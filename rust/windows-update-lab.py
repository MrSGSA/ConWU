"""Offline, isolated end-to-end test of the actual local-update command.

An administrator seeds an independently hashed test MSI as a completed local
download in a GUID validation instance, then invokes the normal authenticated
UI command. Does not alter the download allowlist or the daily installation.
"""
import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import time
import urllib.request
import uuid

ROOT=Path(__file__).resolve().parent.parent


def protect(data):
    class Blob(c.Structure):
        _fields_=[('size',w.DWORD),('data',c.POINTER(c.c_byte))]
    crypt=c.WinDLL('crypt32',use_last_error=True)
    kernel=c.WinDLL('kernel32',use_last_error=True)
    crypt.CryptProtectData.argtypes=[c.POINTER(Blob),w.LPCWSTR,c.POINTER(Blob),c.c_void_p,c.c_void_p,w.DWORD,c.POINTER(Blob)]
    kernel.LocalFree.argtypes=[c.c_void_p]
    buffer=c.create_string_buffer(data)
    before=Blob(len(data),c.cast(buffer,c.POINTER(c.c_byte)))
    after=Blob()
    if not crypt.CryptProtectData(c.byref(before),None,None,None,None,5,c.byref(after)):
        raise c.WinError(c.get_last_error())
    try:
        return b'CWD1'+c.string_at(after.data,after.size)
    finally:
        kernel.LocalFree(after.data)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--instance',required=True)
    parser.add_argument('--package',type=Path,required=True)
    parser.add_argument('--version',required=True)
    parser.add_argument('--expect-failure',action='store_true')
    parser.add_argument('--evidence',type=Path,required=True)
    args=parser.parse_args()
    if uuid.UUID(args.instance).hex!=args.instance:
        raise ValueError('A canonical isolated validation instance is required')
    if not args.evidence.resolve().is_relative_to(ROOT/'out'):
        raise ValueError('Evidence must remain within this worktree/out')
    data=Path(os.environ['ProgramData'])/'ConWU-Validation'/args.instance
    exe=Path(os.environ['ProgramFiles'])/'StreamLink-Validation'/args.instance/'msi/app/ConWU.exe'
    service='StreamLink-Validation-'+args.instance
    def status():
        reply=subprocess.run([str(exe),'--validation-instance',args.instance,'status'],capture_output=True,text=True,encoding='utf-8',timeout=12)
        if reply.returncode:
            raise RuntimeError('Validation service has no control reply yet')
        return json.loads(reply.stdout)
    def public_networks(state):
        return sorted([{'id':n['id'],'ip':n['status']['virtualIp'],'port':n['status']['settings']['listenPort']}
                       for n in state['networks']],key=lambda n:n['id'])
    before=public_networks(status())
    maintenance=Path(json.loads((data/'maintenance-path.json').read_text(encoding='utf-8')))
    old_source=json.loads((maintenance/'current/source.json').read_text(encoding='utf-8'))
    subprocess.run(['sc.exe','stop',service],check=True,capture_output=True)
    deadline=time.monotonic()+80
    while True:
        lock=data/'instance.lock'
        try:
            # Service status is checked via SCM, not by treating a stale panel
            # file as a stopped or started backend.
            check=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',
                "(Get-Service -Name '"+service+"').Status.ToString()"],capture_output=True,text=True,timeout=12)
            if check.stdout.strip()=='Stopped': break
        except subprocess.TimeoutExpired:
            pass
        if time.monotonic()>deadline: raise TimeoutError('Validation service did not stop')
        time.sleep(.3)
    updates=data/'updates'
    updates.mkdir(exist_ok=True)
    target=updates/args.package.name
    shutil.copyfile(args.package,target)
    digest=hashlib.sha256(target.read_bytes()).hexdigest()
    ticket=secrets.token_hex(32)
    (data/'update-ready.private.json').write_bytes(protect(json.dumps(dict(package=str(target),sha256=digest,version=args.version,ticket=ticket)).encode()))
    for name in ('last-update.json','lab-session.private.json','panel.private.json'):
        path=data/name
        if path.is_file() and not path.is_symlink(): path.unlink()
    subprocess.run(['sc.exe','start',service],check=True,capture_output=True)
    deadline=time.monotonic()+250
    while True:
        try:
            s=status()
            if (data/'panel.private.json').is_file() and all(n['status']['adapter']['ready'] for n in s['networks']): break
        except (RuntimeError,ValueError,subprocess.TimeoutExpired): pass
        if time.monotonic()>deadline: raise TimeoutError('Validation backend did not recover before update')
        time.sleep(.5)
    control=json.loads((data/'panel.private.json').read_text(encoding='utf-8'))
    origin=control['origin']
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def request(path,body,cookie=None,csrf=None):
        headers={'Origin':origin,'Content-Type':'application/json'}
        if cookie: headers['Cookie']=cookie
        if csrf: headers['X-StreamLink-CSRF']=csrf
        with opener.open(urllib.request.Request(origin+path,json.dumps(body).encode(),headers),timeout=12) as reply:
            return json.loads(reply.read()),reply.headers
    link,_=request('/api/open',{'secret':control['secret']})
    session,headers=request('/api/session',{'ticket':link['url'].rsplit('#',1)[1]})
    reply,_=request('/api/command',{'method':'update-install','operationId':str(uuid.uuid4()),
        'localUpdate':{'ticket':ticket,'version':args.version}},headers['Set-Cookie'].split(';',1)[0],session['csrf'])
    assert reply['ok'], 'Normal UI update command was rejected'
    deadline=time.monotonic()+650
    installed=None
    while time.monotonic()<deadline:
        try:
            installed=json.loads((data/'last-update.json').read_text(encoding='utf-8'))
            if installed.get('state') in ('Installed','Error'): break
        except (OSError,ValueError): pass
        time.sleep(.5)
    assert installed and installed.get('state')==('Error' if args.expect_failure else 'Installed'), 'Local update did not finish as expected'
    after=status()
    assert all(n['status']['adapter']['ready'] for n in after['networks']), 'Update did not restore enabled adapters'
    assert public_networks(after)==before, 'Update changed network identities, addresses or editor ports'
    new_source=json.loads((maintenance/'current/source.json').read_text(encoding='utf-8'))
    assert (new_source==old_source) if args.expect_failure else (new_source['sha256']==digest), 'Wrong MSI maintenance source after update'
    assert not (maintenance/'pending.json').exists(), 'Unfinished MSI snapshot transaction'
    evidence=dict(normalUiCommand=True,localMsi=True,state=installed['state'],networksPreserved=True,
        adaptersReady=True,maintenanceSourcePreserved=True,productionUntouched=True)
    args.evidence.write_text(json.dumps(evidence,indent=2),encoding='utf-8')
    print(json.dumps(evidence))


if __name__=='__main__':
    main()
