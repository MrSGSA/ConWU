#!/usr/bin/env python3
"""Actual packaged Linux CLI, private profile and no TUN/WAN operations."""
import json,os,pathlib,subprocess,sys,tempfile,time,stat
binary=str(pathlib.Path(sys.argv[1]).resolve());root=pathlib.Path(tempfile.mkdtemp(prefix='conwu-config-cli-'))
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
def start():
 p=subprocess.Popen([binary,'--data',str(root),'run','--no-web'],env=env,stdout=log,stderr=subprocess.STDOUT)
 for _ in range(120):
  if (root/'control.sock').exists():return p
  if p.poll() is not None:raise AssertionError((root/'host.log').read_text())
  time.sleep(.1)
 raise AssertionError('control socket unavailable')
def stop(p):
 if p.poll() is None:
  p.terminate()
  try:p.wait(timeout=75)
  except subprocess.TimeoutExpired:p.kill();p.wait()
proc=start()
try:
 check(run('status')['WorkspaceVersion']==2,'actual packaged host exposes configuration workspace')
 check(stat.S_IMODE((root/'control.sock').stat().st_mode)==0o600,'control socket remains owner-only')
 check(run('network','list')==[],'new profile has no network relationships')
 initial=run('profiles');check(len(initial)==1 and not initial[0]['Networks'],'initial saved configuration is unassociated')
 config_id=initial[0]['Id'];settings=run('profile','export',config_id)
 settings.update(ConnectionSource='existing',DirectMode=True,ExistingEntries=[{'PeerSlot':0,'Source':'entry.example.com#streamlink1'}],EntryRefreshSeconds=75)
 f=root/'connection.json';f.write_text(json.dumps(settings));created=run('profile','create','Linux config',str(f));new_id=created['ConfigurationId']
 chosen=run('profile','show',new_id);check(chosen['Settings']['ExistingEntries'][0]['Source']=='txt://entry.example.com#streamlink1','CLI canonicalizes exact source selectors')
 check(run('network','list')==[],'saving standalone configuration does not create TUN or network')
 settings['EntryRefreshSeconds']=90;f.write_text(json.dumps(settings));run('profile','update',new_id,str(f));check(run('profile','export',new_id)['EntryRefreshSeconds']==90,'CLI updates saved configuration')
 copy=run('profile','copy',new_id,'Linux copy')['ConfigurationId'];run('profile','delete',copy);check(len(run('profiles'))==2,'explicit copy and unused deletion preserve original configurations')
 d=root/'device.json';d.write_text(json.dumps({'DeviceName':'cli-device','LogLevel':'warn'}));run('config','apply',str(d));check(run('config','show')['DeviceName']=='cli-device','device settings are independent of connection configuration')
 settings['RequestedVirtualIp']='10.172.40.1';f.write_text(json.dumps(settings));check('虚拟地址' in run('profile','update',new_id,str(f),success=False),'shared profiles reject a per-network fixed address')
 run('network','invite',success=False);run('network','create',success=False);check(True,'network operations require explicit targets and profiles')
 run('profile','delete',config_id);run('profile','delete',new_id);check(run('profiles')==[],'all unused configurations can be deliberately removed')
 stop(proc);proc=start();check(run('profiles')==[] and run('config','show')['DeviceName']=='cli-device','restart preserves an empty catalog and saved device settings')
 check(run('network','list')==[],'CLI verification creates no business network')
 print(json.dumps({'status':'Pass','scope':'packaged Linux CLI, no TUN/WAN/streaming claim','data':str(root)}),flush=True)
finally:stop(proc);log.close()
