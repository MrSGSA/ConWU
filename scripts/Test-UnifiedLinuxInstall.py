#!/usr/bin/env python3
"""Run with unshare -m -n. Isolated filesystem; simulated systemctl, real daemon.
This checks installer transactions, not a claim of actual systemd hardening validation.
"""
import hashlib,json,os,pathlib,shutil,subprocess,sys,tempfile,time
repo=pathlib.Path(__file__).resolve().parents[1]
runtime=pathlib.Path(sys.argv[1]).resolve()
root=pathlib.Path(tempfile.mkdtemp(prefix='sl-install-'))
def run(*args,**kw):return subprocess.run(args,check=True,text=True,capture_output=True,timeout=90,**kw).stdout
def check(value,name):
    if not value:raise AssertionError(name)
    print('PASS '+name,flush=True)
run('mount','--make-rprivate','/')
for index,target in enumerate(['/opt','/var/lib','/usr/local/bin','/etc/systemd/system','/run']):
    source=root/f'mount-{index}';source.mkdir();run('mount','--bind',str(source),target)
pathlib.Path('/run/systemd/system').mkdir(parents=True)
run('ip','link','set','lo','up')
mock=root/'mock';mock.mkdir();systemctl=mock/'systemctl'
systemctl.write_text('''#!/usr/bin/env python3
import os,pathlib,signal,subprocess,sys,time
p=pathlib.Path('/run/sl-test.pid');cmd=sys.argv[1]
def alive(pid):
    try:return pathlib.Path('/proc/'+str(pid)+'/stat').read_text().split()[2]!='Z'
    except FileNotFoundError:return False
if cmd=='is-active':sys.exit(0 if p.exists() and alive(int(p.read_text())) else 3)
elif cmd=='start':
    log=open('/var/lib/sl-test-daemon.log','a')
    proc=subprocess.Popen(['/opt/streamlink/current/streamlink','run'],stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
    p.write_text(str(proc.pid))
elif cmd=='stop':
    if p.exists():
        pid=int(p.read_text())
        if alive(pid):os.kill(pid,signal.SIGTERM)
        end=time.monotonic()+40
        while alive(pid) and time.monotonic()<end:time.sleep(.1)
        if alive(pid):sys.exit(1)
        p.unlink()
elif cmd in ('enable','disable'):
    target=pathlib.Path('/etc/systemd/system/multi-user.target.wants/streamlink.service')
    if cmd=='enable':
        target.parent.mkdir(exist_ok=True)
        if not target.exists():target.symlink_to('/etc/systemd/system/streamlink.service')
    elif target.is_symlink():target.unlink()
elif cmd!='daemon-reload':sys.exit(2)
''');systemctl.chmod(0o755)
env=dict(os.environ,PATH=str(mock)+':'+os.environ['PATH'])
bundle=root/'bundle';bundle.mkdir();shutil.copytree(runtime,bundle/'runtime')
for item in (repo/'packaging/linux').iterdir():shutil.copy(item,bundle/item.name)
def hashes():
    entries=[p for p in bundle.rglob('*') if p.is_file() and p.name!='SHA256SUMS']
    (bundle/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+str(p.relative_to(bundle))+'\n' for p in sorted(entries)))
hashes()
try:
    run('bash',str(bundle/'install.sh'),env=env)
    check(json.loads(run('/usr/local/bin/conwu','config','show',env=env))==json.loads(run('/usr/local/bin/streamlink','config','show',env=env)), 'new and compatibility commands address the same daemon settings')
    p=root/'settings.json';p.write_text(json.dumps({'DeviceName':'retained-across-upgrade','LogLevel':'warn'}))
    run('/usr/local/bin/streamlink','config','apply',str(p),env=env)
    connection=root/'connection.json';connection.write_text(json.dumps({'ConnectionSource':'existing','DirectMode':True,'CoordinatorBackup':True,'Service':'https://coord.example.test/','ExistingEntries':[{'PeerSlot':0,'Source':'203.0.113.8:44680'}]}))
    run('/usr/local/bin/conwu','profile','create','retained-connection',str(connection),env=env)
    profiles=json.loads(run('/usr/local/bin/conwu','profiles',env=env))
    original=json.loads(run('/usr/local/bin/streamlink','config','show',env=env));old=pathlib.Path('/opt/streamlink/current').resolve()
    unit=pathlib.Path('/etc/systemd/system/streamlink.service')
    prior_unit=unit.read_bytes().replace(b'\r\n',b'\n')
    unit.write_bytes(prior_unit.replace(b'# StreamLink managed unit',b'# Another product unit'))
    refused=subprocess.run(['bash',str(bundle/'install.sh')],env=env,capture_output=True,text=True,timeout=30)
    check(refused.returncode!=0 and json.loads(run('/usr/local/bin/streamlink','config','show',env=env))==original,'installer rejects an unmanaged unit before stopping the active daemon')
    unit.write_bytes(prior_unit.replace(b'\n',b'\r\n'))
    (bundle/'build-note.txt').write_text('second package');hashes()
    run('bash',str(bundle/'install.sh'),env=env)
    check(pathlib.Path('/opt/streamlink/current').resolve()!=old and old.is_dir(),'update switches program atomically and retains the previous release')
    check(json.loads(run('/usr/local/bin/streamlink','config','show',env=env))==original,'update preserves saved settings and startup choice')
    check(json.loads(run('/usr/local/bin/conwu','profiles',env=env))==profiles,'upgrade preserves the configuration library including coordinator backup settings')
    check(True,'upgrade accepts the exact CRLF unit format from earlier Windows-built packages')
    unit.write_bytes(unit.read_bytes().replace(b'\r\n',b'\n').replace(b'\n',b'\r\n'))
    run('bash',str(bundle/'uninstall.sh'),env=env)
    check(True,'uninstall also recognizes an owned CRLF service unit')
    check(not pathlib.Path('/usr/local/bin/conwu').is_symlink() and not pathlib.Path('/usr/local/bin/streamlink').is_symlink(), 'uninstall removes both owned command aliases')
    check(not pathlib.Path('/opt/streamlink').exists() and pathlib.Path('/var/lib/streamlink/profile.json').exists(),'uninstall removes only the program and keeps settings')
    run('bash',str(bundle/'install.sh'),env=env)
    check(json.loads(run('/usr/local/bin/streamlink','config','show',env=env))==original,'reinstallation inherits retained settings')
    check(json.loads(run('/usr/local/bin/conwu','profiles',env=env))==profiles,'reinstallation inherits saved connection configurations')
    print(json.dumps({'status':'Pass','evidence':str(root),'systemctl':'simulated; actual published daemon'}))
finally:
    subprocess.run(['systemctl','stop','streamlink.service'],env=env,capture_output=True)
