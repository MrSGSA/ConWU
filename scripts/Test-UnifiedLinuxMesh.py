#!/usr/bin/env python3
"""Production CLI, HTTPS coordinator, TUN and FakeTCP across two isolated Linux namespaces."""
import hashlib, json, os, pathlib, shutil, ssl, subprocess, sys, tempfile, time, uuid

binary=str(pathlib.Path(sys.argv[1]).resolve())
protocol='udp' if '--udp' in sys.argv else 'faketcp'
root=pathlib.Path(tempfile.mkdtemp(prefix='sl-mesh-'))
names=['sltest-'+uuid.uuid4().hex[:10] for _ in range(2)]
hosts=[];logs=[];checks=[]
def run(*args,**kw):
    result=subprocess.run(args,text=True,capture_output=True,timeout=80,**kw)
    if result.returncode:
        raise AssertionError(f'Command failed ({result.returncode}): {args!r}\n{result.stdout}\n{result.stderr}')
    return result.stdout
def cmd(i,*args):return ['ip','netns','exec',names[i],*args]
def cli(i,*args):
    return json.loads(run(*cmd(i,binary,*args),env=dict(os.environ,STREAMLINK_PROFILE_ROOT=str(root/str(i)))))
def check(value,description):
    if not value:raise AssertionError(description)
    checks.append(description);print('PASS '+description,flush=True)
def wait(action,limit=35):
    end=time.monotonic()+limit
    while time.monotonic()<end:
        result=action()
        if result:return result
        time.sleep(.25)
    raise AssertionError('Timed out: '+str(action))
def apply(i,value):
    p=root/f'apply-{i}.json';p.write_text(json.dumps(value));return cli(i,'config','apply',str(p))
try:
    print('Evidence: '+str(root),flush=True)
    for i,name in enumerate(names):
        run('ip','netns','add',name);run(*cmd(i,'ip','link','set','lo','up'))
    run('ip','link','add','slv0','type','veth','peer','name','slv1')
    for i in range(2):
        run('ip','link','set',f'slv{i}','netns',names[i])
        run(*cmd(i,'ip','link','set','lo','up'))
        run(*cmd(i,'ip','addr','add',f'203.0.113.{i+1}/24','dev',f'slv{i}'))
        run(*cmd(i,'ip','link','set',f'slv{i}','up'))
        (root/str(i)).mkdir(mode=0o700)
    cert=root/'cert.pem';key=root/'key.pem'
    run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=streamlink-test','-addext','subjectAltName=IP:203.0.113.1')
    pin=hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest().upper()
    for i in range(2):
        log=open(root/f'host-{i}.log','w');logs.append(log)
        hosts.append(subprocess.Popen(cmd(i,binary,'run','--no-web'),env=dict(os.environ,STREAMLINK_PROFILE_ROOT=str(root/str(i))),stdout=log,stderr=subprocess.STDOUT))
        wait(lambda:(root/str(i)/'control.sock').exists())
        settings={'Service':'https://203.0.113.1:47822/','CertificatePin':pin,'ConnectionSource':'existing',
                  'PathSelection':protocol+'-only',
                  'ExistingEntries':[{'PeerSlot':0,'Source':f'203.0.113.{i+1}:44680'},{'PeerSlot':-2,'Source':f'203.0.113.{2-i}:44680'}]}
        if i==0:settings['Coordinator']={'Enabled':True,'ListenUrl':'https://0.0.0.0:47822','CertificateFile':str(cert),'CertificateKeyFile':str(key)}
        apply(i,{'DeviceName':f'Linux-{i}','Network':settings})
    wait(lambda:cli(0,'status')['Coordinator']['Running'])
    cli(0,'network','create');state=cli(0,'status');code=state['Pairing']['Code'];network=state['NetworkId']
    cli(1,'network','join',code)
    def poll():
        cli(0,'network','poll');cli(1,'network','poll')
        return cli(0,'status').get('Pairing',{}).get('Verification')
    verification=wait(poll)
    check(verification==cli(1,'status')['Pairing']['Verification'],'both Linux devices show matching pairing verification')
    cli(0,'network','approve',verification)
    wait(lambda:cli(1,'network','poll')['Status']['NetworkId']==network)
    connected=lambda:all(any(p['Connected'] for p in cli(i,'status')['Peers']) for i in range(2))
    wait(connected,60)
    a,b=cli(0,'status'),cli(1,'status')
    check(a['Coordinator']['Running'] and a['CanManageNetwork'] and b['CanManageNetwork'],'coordinator also participates as an equal ordinary member')
    run(*cmd(1,'ping','-c','4','-W','2',a['VirtualIp']))
    check(True,'real IP packets pass through both TUNs and '+protocol)
    before=cli(1,'config','show')
    hosts[1].kill();hosts[1].wait(timeout=10)
    hosts[1]=subprocess.Popen(cmd(1,binary,'run','--no-web'),env=dict(os.environ,STREAMLINK_PROFILE_ROOT=str(root/'1')),stdout=logs[1],stderr=subprocess.STDOUT)
    time.sleep(1)
    wait(connected,60)
    check(cli(1,'config','show')==before,'abrupt daemon exit recovers rules and reconnects with the same settings')
    apply(0,{'Network':{'Coordinator':{'Enabled':False}}})
    wait(lambda:not cli(0,'status')['Coordinator']['Running'])
    run(*cmd(1,'ping','-c','4','-W','2',a['VirtualIp']))
    check(True,'disabling coordination retains the authenticated business connection')
    apply(0,{'Network':{'Coordinator':{'Enabled':True}}});wait(lambda:cli(0,'status')['Coordinator']['Running'])
    cli(1,'network','invite');check(len(cli(1,'status')['Pairing']['Code'])==6,'a non-creator can invite another member')
    cli(1,'network','leave',network)
    check(cli(1,'config','show')==before,'leaving preserves all saved Linux settings')
    cli(0,'network','close',network)
    check(not cli(0,'status')['NetworkId'] and cli(0,'status')['Coordinator']['Running'],'dissolving membership leaves the independent coordination role running')
    for i,host in enumerate(hosts):
        host.terminate();check(host.wait(timeout=40)==0,'Linux daemon exits cleanly')
        check('table inet sl_' not in run(*cmd(i,'nft','list','tables')) and 'StreamLink-' not in run(*cmd(i,'iptables','-S','INPUT')),'all owned firewall rules are removed without deleting system tables')
    print(json.dumps({'status':'Pass','checks':checks,'evidence':str(root)},ensure_ascii=False))
finally:
    for host in hosts:
        if host.poll() is None:
            host.terminate()
            try:host.wait(timeout=40)
            except subprocess.TimeoutExpired:host.kill();host.wait()
    for log in logs:log.close()
    evidence=pathlib.Path(__file__).resolve().parents[1]/'artifacts'/'unified-linux-mesh'/root.name
    for log in root.rglob('*.log'):
        target=evidence/log.relative_to(root);target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(log,target)
    print('Retained logs: '+str(evidence),flush=True)
    for name in names:subprocess.run(['ip','netns','del',name],capture_output=True)
