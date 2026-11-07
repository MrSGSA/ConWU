#!/usr/bin/env python3
"""Run under unshare -Urnm: mount-isolated paths and fake systemctl/install.
No real services, adapters or DNS are touched; this tests transaction ordering.
"""
import hashlib, os, pathlib, shutil, subprocess, tempfile
repo=pathlib.Path(__file__).resolve().parents[1]
root=pathlib.Path(tempfile.mkdtemp(prefix='conwu-fresh-test-'))
def run(*args,**kw):return subprocess.run(args,text=True,capture_output=True,timeout=40,**kw)
def must(*args,**kw):
 p=run(*args,**kw)
 if p.returncode:raise RuntimeError(f'{args}: {p.stderr}')
 return p
must('mount','--make-rprivate','/')
for i,target in enumerate(['/opt','/var/lib','/usr/local/bin','/etc/systemd/system','/run']):
 src=root/f'bind-{i}';src.mkdir();must('mount','--bind',str(src),target)
mock=root/'mock';mock.mkdir()
(mock/'systemctl').write_text('''#!/usr/bin/env python3
import os,pathlib,sys
state=pathlib.Path('/run/service-active');enabled=pathlib.Path('/run/service-enabled');action=sys.argv[1]
if action=='is-active':sys.exit(0 if state.exists() else 3)
if action=='is-enabled':sys.exit(0 if enabled.exists() else 1)
if action=='stop':
 count=pathlib.Path('/run/stop-count');n=int(count.read_text())+1 if count.exists() else 1;count.write_text(str(n))
 if os.environ.get('FAIL_STOP')=='1' or os.environ.get('FAIL_STOP_SECOND')=='1' and n>1:sys.exit(1)
 state.unlink(missing_ok=True)
elif action=='start':state.touch()
elif action=='enable':enabled.touch()
elif action=='disable':enabled.unlink(missing_ok=True)
elif action!='daemon-reload':sys.exit(2)
''');(mock/'systemctl').chmod(0o755)
env=dict(os.environ,PATH=str(mock)+':'+os.environ['PATH'])
bundle=root/'bundle';bundle.mkdir()
(bundle/'install.sh').write_text('''#!/usr/bin/env bash
set -euo pipefail
[[ ${CONWU_INSTALL_LOCK_INHERITED:-} == 1 && $(readlink /proc/$$/fd/9) == /opt/streamlink/install.lock ]]
mkdir -p /opt/streamlink/releases/new
printf '#!/bin/sh\\nexit 0\\n' > /opt/streamlink/releases/new/conwu
chmod +x /opt/streamlink/releases/new/conwu
ln -sfn /opt/streamlink/releases/new /opt/streamlink/current
ln -sfn /opt/streamlink/current/conwu /usr/local/bin/conwu
printf '# StreamLink managed unit\\nnew unit\\n' > /etc/systemd/system/streamlink.service
printf new > /var/lib/streamlink/new-profile
[[ ${FAIL_INSTALL:-} != 1 ]]
''');(bundle/'install.sh').chmod(0o755)
(bundle/'runtime').mkdir()
(bundle/'runtime/conwu').write_text('''#!/usr/bin/env python3
import os,json
assert os.environ.get('STREAMLINK_PROFILE_ROOT')=='/var/lib/streamlink'
print(json.dumps({'schemaVersion':1,'complete':os.environ.get('UNVERIFIED')!='1','ownedResources':[]}))
''');(bundle/'runtime/conwu').chmod(0o755)
(bundle/'SHA256SUMS').write_text(hashlib.sha256((bundle/'install.sh').read_bytes()).hexdigest()+'  install.sh\n'+hashlib.sha256((bundle/'runtime/conwu').read_bytes()).hexdigest()+'  runtime/conwu\n')
hashvalue=hashlib.sha256((bundle/'SHA256SUMS').read_bytes()).hexdigest()
script=repo/'packaging/linux/fresh-install.sh'
def reset():
 for path in ['/opt','/var/lib','/usr/local/bin','/etc/systemd/system','/run']:
  for p in pathlib.Path(path).iterdir():
   if p.is_dir() and not p.is_symlink():shutil.rmtree(p)
   else:p.unlink()
 old=pathlib.Path('/opt/streamlink/releases/old');old.mkdir(parents=True)
 (old/'conwu').write_text('#!/bin/sh\nprintf \'{"schemaVersion":1,"complete":true,"ownedResources":[]}\\n\'\n');(old/'conwu').chmod(0o755)
 pathlib.Path('/opt/streamlink/current').symlink_to(old)
 pathlib.Path('/var/lib/backups').mkdir()
 pathlib.Path('/var/lib/streamlink/networks/a').mkdir(parents=True)
 pathlib.Path('/var/lib/streamlink/networks/a/profile.json').write_text('old-secret')
 pathlib.Path('/etc/systemd/system/streamlink.service').write_text('# StreamLink managed unit\nold unit\n')
 pathlib.Path('/etc/systemd/system/ssh.service').write_text('ssh untouched')
 pathlib.Path('/opt/easytier').mkdir();pathlib.Path('/opt/easytier/keep').write_text('keep')
 pathlib.Path('/run/service-active').touch();pathlib.Path('/run/service-enabled').touch()
def check(x,msg):
 if not x:raise AssertionError(msg)
 print('PASS '+msg,flush=True)
def invoke(**extra):return run('bash',str(script),str(bundle),hashvalue,'/var/lib/backups',env=env|extra)
reset();p=invoke();print(p.stderr,flush=True) if p.returncode else None;check(p.returncode==0,'fresh install completes with verified empty ownership report')
backup=next(pathlib.Path('/var/lib/backups').glob('conwu-fresh-*'));check((backup/'data-stopped.tar').exists() and (backup/'previous-package.tar').exists() and (backup/'candidate-package.tar').exists(),'both packages and stopped data are backed up')
check(pathlib.Path('/var/lib/streamlink/new-profile').read_text()=='new' and list(pathlib.Path('/var/lib').glob('streamlink.preinstall-*/networks/a/profile.json'))[0].read_text()=='old-secret','old data is quarantined and new profile remains separate')
check(pathlib.Path('/opt/easytier/keep').read_text()=='keep' and pathlib.Path('/etc/systemd/system/ssh.service').read_text()=='ssh untouched','independent management services remain untouched')
reset();p=invoke(FAIL_INSTALL='1');check(p.returncode!=0,'injected installation failure is reported')
check(pathlib.Path('/var/lib/streamlink/networks/a/profile.json').read_text()=='old-secret' and pathlib.Path('/opt/streamlink/current').resolve().name=='old' and pathlib.Path('/run/service-active').exists(),'failure restores previous data, release and running state')
reset();p=invoke(FAIL_INSTALL='1',FAIL_STOP_SECOND='1');check(p.returncode!=0 and pathlib.Path('/var/lib/streamlink/new-profile').exists() and list(pathlib.Path('/var/lib').glob('streamlink.preinstall-*/networks/a/profile.json')),'failed rollback stop leaves old data isolated')
reset();p=invoke(FAIL_STOP='1');check(p.returncode!=0 and pathlib.Path('/var/lib/streamlink/networks/a/profile.json').read_text()=='old-secret','failure to stop leaves old data in place')
reset();p=invoke(UNVERIFIED='1');check(p.returncode!=0 and pathlib.Path('/var/lib/streamlink/networks/a/profile.json').exists() and pathlib.Path('/run/service-active').exists(),'unverified adapter ownership blocks transition and restores service')
reset();pathlib.Path('/etc/systemd/system/streamlink.service').write_text('foreign service\n');p=invoke();check(p.returncode!=0 and pathlib.Path('/run/service-active').exists(),'foreign service is rejected before stop')
print('PASS isolated mock fresh-install transaction; no physical service validation')
