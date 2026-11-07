#!/usr/bin/env python3
"""Actual Linux Host under unshare -Urn, isolated profile; no WAN claims."""
import json,os,pathlib,subprocess,sys,tempfile,time
binary=str(pathlib.Path(sys.argv[1]).resolve());root=pathlib.Path(tempfile.mkdtemp(prefix='conwu-pair-cli-'))
log=(root/'host.log').open('w');env=dict(os.environ)
def run(*args,success=True):
 p=subprocess.run([binary,'--data',str(root),*args],env=env,text=True,capture_output=True,timeout=40)
 if success and p.returncode:raise AssertionError(f'{args}: {p.stderr} {p.stdout}')
 if not success:
  if not p.returncode:raise AssertionError(f'{args}: should fail')
  return p.stderr
 return json.loads(p.stdout)
def check(ok,msg):
 if not ok:raise AssertionError(msg)
 print('PASS '+msg,flush=True)
proc=subprocess.Popen([binary,'--data',str(root),'run','--no-web'],env=env,stdout=log,stderr=subprocess.STDOUT)
try:
 for i in range(120):
  if (root/'control.sock').exists():break
  if proc.poll() is not None:raise AssertionError((root/'host.log').read_text())
  time.sleep(.1)
 check(run('status')['WorkspaceVersion']==1,'actual service enables workspace')
 check(run('network','list')==[],'new profile has no relationships')
 run('start',success=False);run('network','invite',success=False);check(True,'network-targeted commands reject omitted configuration ID')
 error=run('network','create',success=False);check('协调' in error,'autonomous mode without coordinator is rejected')
 f=root/'config-input.json';f.write_text(json.dumps({'DeviceName':'cli-device','Network':{'ConnectionSource':'existing'}}));run('config','apply',str(f));check(run('config','show')['DeviceName']=='cli-device','device defaults save through batch transaction')
 run('network','create');run('network','create');items=run('network','list');check(len(items)==2 and items[0]['configurationId']!=items[1]['configurationId'],'two creations use independent configuration IDs')
 a,b=items[0]['configurationId'],items[1]['configurationId'];run('network','rename',a,'网络甲');check(run('network','status',a)['SelectedNetworkId']==a,'status selects intended configuration')
 f.write_text(json.dumps({'Network':{'EntryRefreshSeconds':75}}));run('config','apply',str(f),'--network',a)
 check(run('config','show','--network',a)['Network']['EntryRefreshSeconds']==75 and run('config','show','--network',b)['Network']['EntryRefreshSeconds']!=75,'network settings do not change another network')
 run('network','remove-config',a);remaining=run('network','list');check(len(remaining)==1 and remaining[0]['configurationId']==b,'remove targets only selected relationship')
 run('network','status',a,success=False);check(run('network','status',b)['SelectedNetworkId']==b,'removed target fails and remaining relationship survives')
 print('PASS actual Linux CLI workspace; no WAN or streaming claim')
finally:
 if proc.poll() is None:
  proc.terminate()
  try:proc.wait(timeout=75)
  except subprocess.TimeoutExpired:proc.kill();proc.wait()
 log.close()
