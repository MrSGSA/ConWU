#!/usr/bin/env python3
"""Real Host/TUN/FakeTCP in isolated Linux namespaces; no physical WAN claim.
Run under unshare -Urnm with an isolated /run mount. The test owns only its
randomly named namespaces and their veth interfaces.
"""
import hashlib,json,os,pathlib,shutil,ssl,subprocess,sys,tempfile,time,uuid
binary=str(pathlib.Path(sys.argv[1]).resolve());root=pathlib.Path(tempfile.mkdtemp(prefix='conwu-pair-mesh-'))
runroot=root/'run';runroot.mkdir();subprocess.run(['mount','--bind',str(runroot),'/run'],check=True)
ids=['cw-'+uuid.uuid4().hex[:10] for _ in range(3)];bridge='cwb'+uuid.uuid4().hex[:8];hosts=[];logs=[];checks=[]
def run(*args,**kw):
 r=subprocess.run(args,text=True,capture_output=True,timeout=90,**kw)
 if r.returncode:raise AssertionError(f'{args}: {r.stderr} {r.stdout}')
 return r.stdout
def ns(i,*args):return ['ip','netns','exec',ids[i],*args]
def cli(i,*args):return json.loads(run(*ns(i,binary,'--data',str(root/str(i)),*args)))
def check(ok,msg):
 if not ok:raise AssertionError(msg)
 checks.append(msg);print('PASS '+msg,flush=True)
def wait(fn,seconds=50):
 end=time.monotonic()+seconds;last=None
 while time.monotonic()<end:
  try:
   r=fn()
   if r:return r
  except (AssertionError,KeyError,TypeError) as e:last=e
  time.sleep(.3)
 raise AssertionError(f'timed out: {last}')
def state(i,id):return cli(i,'network','status',id)
def apply(i,obj):
 p=root/f'config-{i}.json';p.write_text(json.dumps(obj));return cli(i,'config','apply',str(p))
try:
 print('Evidence: '+str(root),flush=True)
 run('ip','link','add',bridge,'type','bridge');run('ip','link','set',bridge,'up')
 for i,name in enumerate(ids):
  run('ip','netns','add',name);run(*ns(i,'ip','link','set','lo','up'))
  outer='co'+uuid.uuid4().hex[:8];inner='ci'+uuid.uuid4().hex[:8]
  run('ip','link','add',outer,'type','veth','peer','name',inner);run('ip','link','set',outer,'master',bridge);run('ip','link','set',outer,'up');run('ip','link','set',inner,'netns',name)
  run(*ns(i,'ip','addr','add',f'203.0.113.{i+1}/24','dev',inner));run(*ns(i,'ip','link','set',inner,'up'));(root/str(i)).mkdir(mode=0o700)
 cert=root/'cert.pem';key=root/'key.pem';run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=conwu-test','-addext','subjectAltName=IP:203.0.113.1')
 pin=hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest().upper()
 for i in range(3):
  log=(root/f'host-{i}.log').open('w');logs.append(log);hosts.append(subprocess.Popen(ns(i,binary,'--data',str(root/str(i)),'run','--no-web'),stdout=log,stderr=subprocess.STDOUT))
  wait(lambda:(root/str(i)/'control.sock').exists())
  settings={'Service':'https://203.0.113.1:47822/','CertificatePin':pin,'ConnectionSource':'existing','PathSelection':'faketcp-only','ExistingEntries':[{'PeerSlot':0,'Source':f'203.0.113.{i+1}:44680'},{'PeerSlot':-2,'Source':f'203.0.113.{2 if i==0 else 1}:44680'}]}
  if i==0:settings['Coordinator']={'Enabled':True,'ListenUrl':'https://0.0.0.0:47822','CertificateFile':str(cert),'CertificateKeyFile':str(key)}
  apply(i,{'DeviceName':f'Linux-{i}','Network':settings})
 wait(lambda:cli(0,'coordinator','status')['Running'])
 pairs=[]
 for guest in (1,2):
  created=cli(0,'network','create')['Status'];aid=created['SelectedNetworkId'];code=created.get('Pairing',{}).get('Code')
  if guest==2:
   p=root/'network-c.json';p.write_text(json.dumps({'Network':{'ExistingEntries':[{'PeerSlot':0,'Source':'203.0.113.1:44680'},{'PeerSlot':-2,'Source':'203.0.113.3:44680'}]}}));cli(0,'config','apply',str(p),'--network',aid)
  if not code:cli(0,'network','invite',aid);code=state(0,aid)['Pairing']['Code']
  joined=cli(guest,'network','join',code)['Status'];bid=joined['SelectedNetworkId']
  def ready():
   cli(0,'network','poll',aid);cli(guest,'network','poll',bid)
   a=state(0,aid).get('Pairing') or {};b=state(guest,bid).get('Pairing') or {}
   return a.get('Verification') if a.get('Verification') and a.get('Verification')==b.get('Verification') else None
  verify=wait(ready);cli(0,'network','approve',aid,verify)
  wait(lambda:bool((cli(guest,'network','poll',bid)['Status']['NetworkId'])))
  pairs.append((aid,bid));check(True,f'independent approval completes for guest {guest}')
 def connected():return all(any(p['Connected'] for p in state(0,a)['Peers']) and any(p['Connected'] for p in state(i,b)['Peers']) for i,(a,b) in enumerate(pairs,1))
 try:wait(connected,90)
 except Exception:
  for i in range(3):
   snapshot=cli(i,'status');(root/f'status-{i}.json').write_text(json.dumps(snapshot,ensure_ascii=False,indent=2));print('STATE',i,[(n['Name'],n['Status']['State'],n['Status'].get('Connection')) for n in snapshot['Networks']],flush=True)
  raise
 host0=[state(0,a) for a,_ in pairs];guest0=[state(i,b) for i,(_,b) in enumerate(pairs,1)]
 check(host0[0]['Settings']['ListenPort']==host0[1]['Settings']['ListenPort'],'two networks share the same physical receive port')
 check(host0[0]['VirtualIp']!=host0[1]['VirtualIp'],'two network adapters have distinct virtual addresses')
 for i in (1,2):
  run(*ns(i,'ping','-c','3','-W','2',host0[i-1]['VirtualIp']));run(*ns(0,'ping','-c','3','-W','2',guest0[i-1]['VirtualIp']))
 check(True,'both directions pass real TUN packets through FakeTCP on both pairs')
 cli(1,'network','leave',pairs[0][1]);run(*ns(2,'ping','-c','3','-W','2',host0[1]['VirtualIp']));check(True,'one relationship exits without disrupting the other')
 cli(0,'network','remove-config',pairs[0][0])
 for i in (0,1):apply(i,{'Network':{'Service':'','CertificatePin':'','ConnectionSource':'existing'}})
 direct=cli(0,'network','create')['Status'];directId=direct['SelectedNetworkId'];invite=cli(0,'network','invite',directId)['Status']['Pairing']['Code'];check(invite.startswith('SL6.'),'explicit direct invitation identifies the target network')
 directGuest=cli(1,'network','join',invite)['Status']['SelectedNetworkId']
 def directReady():
  cli(0,'network','poll',directId);cli(1,'network','poll',directGuest)
  a=state(0,directId).get('Pairing') or {};b=state(1,directGuest).get('Pairing') or {}
  return a.get('Verification') if a.get('Verification') and a.get('Verification')==b.get('Verification') else None
 verify=wait(directReady);cli(0,'network','approve',directId,verify);wait(lambda:bool(cli(1,'network','poll',directGuest)['Status']['NetworkId']))
 wait(lambda:any(p['Connected'] for p in state(1,directGuest)['Peers']),90)
 run(*ns(1,'ping','-c','3','-W','2',state(0,directId)['VirtualIp']));check(True,'direct invitation joins and sends through real native/TUN while another network remains active')
 hosts[2].kill();hosts[2].wait(timeout=10);hosts[2]=subprocess.Popen(ns(2,binary,'--data',str(root/'2'),'run','--no-web'),stdout=logs[2],stderr=subprocess.STDOUT)
 wait(lambda:(root/'2'/'control.sock').exists());wait(lambda:any(p['Connected'] for p in state(2,pairs[1][1])['Peers']),90)
 run(*ns(2,'ping','-c','3','-W','2',host0[1]['VirtualIp']));check(True,'restart recovers remaining relationship and traffic')
 print(json.dumps({'status':'Pass','checks':checks,'evidence':str(root)},ensure_ascii=False))
finally:
 for proc in hosts:
  if proc.poll() is None:
   proc.terminate()
   try:proc.wait(timeout=65)
   except subprocess.TimeoutExpired:proc.kill();proc.wait()
 for f in logs:f.close()
 evidence=pathlib.Path(__file__).resolve().parents[1]/'artifacts'/'pair-linux-mesh'/root.name
 for f in list(root.rglob('*.log'))+list(root.glob('status-*.json')):
  target=evidence/f.relative_to(root);target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(f,target)
 print('Retained logs: '+str(evidence),flush=True)
 for name in ids:subprocess.run(['ip','netns','del',name],capture_output=True)
 subprocess.run(['ip','link','del',bridge],capture_output=True)
