"""Bounded TCP birthday experiment, disabled unless --enabled is supplied.

Creates two SNAT routers and an isolated transit bridge. All peer SYNs are
active opens; there is no DNAT, explicit mapping API or business relay. The
reduced configurable port space tests the mechanism, not Internet success
rates. Payload authentication is an independent HMAC fixture, not ConWU
membership, SAS approval or MeshLink. No upstream code is executed/copied.
"""
import argparse
import asyncio
import hmac
import json
import math
import os
from pathlib import Path
import secrets
import signal
import socket
import struct
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = Path(__file__).resolve()
TRANSIT, A_WAN, B_WAN = '192.0.2.254', '192.0.2.10', '192.0.2.20'
OBSERVER_PORT, STABLE_PORT = 39000, 38000


def save(path, value):
    temp = path.with_name('.'+path.name+'.tmp')
    temp.write_text(json.dumps(value, indent=2), encoding='utf-8')
    temp.replace(path)


def run(*args, data=None, check=True):
    result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=15)
    if check and result.returncode:
        raise RuntimeError(str(args)+': '+result.stderr[-1800:])
    return result.stdout


async def observer():
    async def serve(reader, writer):
        try:
            writer.write((json.dumps(writer.get_extra_info('peername'))+'\n').encode())
            await writer.drain()
            await reader.read(1)
        except ConnectionResetError:
            pass
        finally:
            writer.close()
    servers = [await asyncio.start_server(serve, TRANSIT, port)
               for port in range(OBSERVER_PORT,OBSERVER_PORT+17)]
    await asyncio.gather(*(server.serve_forever() for server in servers))


def capture(path):
    running = True
    def stop(*_):
        nonlocal running
        running = False
    signal.signal(signal.SIGTERM, stop)
    interface = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    interface.bind(('wan0', 0))
    interface.settimeout(.2)
    count = 0
    with path.open('w', encoding='utf-8', buffering=1) as file:
        while running and count < 16384:
            try:
                packet = interface.recv(65535)[14:]
            except socket.timeout:
                continue
            if len(packet) < 40 or packet[0]>>4 != 4 or packet[9] != 6:
                continue
            ihl = (packet[0]&15)*4
            if ihl < 20 or len(packet) < ihl+20:
                continue
            src, dst = socket.inet_ntoa(packet[12:16]), socket.inet_ntoa(packet[16:20])
            if {src, dst} != {A_WAN, B_WAN}:
                continue
            sport, dport, seq, ack = struct.unpack('!HHII', packet[ihl:ihl+12])
            flags = packet[ihl+13]
            if not flags & 7:
                continue
            file.write(json.dumps(dict(at=time.monotonic(), src=src, dst=dst,
                sport=sport, dport=dport, seq=seq, ack=ack, flags=flags))+'\n')
            count += 1
    interface.close()


def tcp(local_ip, port, abortive=False):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if abortive:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii',1,0))
    sock.bind((local_ip, port))
    sock.setblocking(False)
    return sock


async def node(config):
    role = config['role']
    folder = Path(config['folder'])
    local = '10.71.0.2' if role == 'a' else '10.72.0.2'
    key, session = bytes.fromhex(config['key']), bytes.fromhex(config['session'])
    held = None
    if role == 'a':
        sock = tcp(local, STABLE_PORT, abortive=True)
        await asyncio.get_running_loop().sock_connect(sock, (TRANSIT, config['observerPort']))
        reader, writer = await asyncio.open_connection(sock=sock)
        candidate = json.loads(await reader.readline())
        held = writer
        save(folder/'candidate.private.json', candidate)
    while not (folder/'go.private.json').is_file():
        await asyncio.sleep(.02)
    go = json.loads((folder/'go.private.json').read_text())
    await asyncio.sleep(max(0,go['start']+(.2 if role=='a' else 0)-time.monotonic()))
    candidate = tuple(go['candidate'])
    targets = [(B_WAN, p) for p in go['targets']] if role=='a' else [candidate]*config['mappings']
    successes, errors = [], {}
    message = b'CWBD1'+role.encode()+session+secrets.token_bytes(1024)
    message += hmac.digest(key,message,'sha256')
    async def probe(target):
        sock = tcp(local, STABLE_PORT if role=='a' else 0)
        source = sock.getsockname()
        writer = None
        try:
            async with asyncio.timeout(config['seconds']):
                await asyncio.get_running_loop().sock_connect(sock,target)
                reader, writer = await asyncio.open_connection(sock=sock)
                writer.write(message)
                await writer.drain()
                remote = await reader.readexactly(len(message))
                assert remote[:5]==b'CWBD1' and remote[5:6] != role.encode()
                assert remote[6:22]==session and hmac.compare_digest(
                    hmac.digest(key,remote[:-32],'sha256'),remote[-32:])
                writer.write(b'ACK'+hmac.digest(key,remote,'sha256'))
                await writer.drain()
                assert await reader.readexactly(35)==b'ACK'+hmac.digest(key,message,'sha256')
                successes.append(dict(local=source,peer=sock.getpeername(),authenticatedBytes=len(remote)))
        except (OSError, TimeoutError, asyncio.IncompleteReadError, AssertionError) as error:
            name = type(error).__name__
            errors[name] = errors.get(name,0)+1
        finally:
            if writer:
                writer.close()
            else:
                sock.close()
    await asyncio.gather(*(probe(target) for target in targets))
    if held:
        held.close()
    save(folder/('result-'+role+'.private.json'),dict(role=role,attempts=len(targets),
         successes=successes,errors=errors))


def isolated(args):
    if not args.enabled:
        raise SystemExit('Experiment disabled: explicitly pass --enabled inside birthday-nat-lab.sh')
    if os.geteuid()!=0 or not Path('/run/netns').is_dir():
        raise SystemExit('Use the private mount/network-namespace wrapper as root')
    if not (1<=args.mappings<=128 and 1<=args.probes<=128 and 1<=args.rounds<=8
            and 64<=args.port_space<=64512 and 1<=args.seconds<=8):
        raise SystemExit('Experiment exceeds the socket, port, round or time budget')
    token = uuid.uuid4().hex[:8]
    folder = ROOT/'out/lab'/('birthday-'+token)
    folder.mkdir()
    names = ['cwbd-'+token+'-'+suffix for suffix in ('a','b','ra','rb','c')]
    created, children, logs, summaries = [], [], [], []
    low, high = 1024, 1023+args.port_space
    def inside(index,*command,data=None,check=True):
        return run('ip','netns','exec',names[index],*command,data=data,check=check)
    def launch(index,*command):
        log = (folder/('process-'+str(len(logs))+'.log')).open('wb')
        logs.append(log)
        process = subprocess.Popen(['ip','netns','exec',names[index],*command],stdout=log,stderr=log)
        children.append(process)
        return process
    def wait_file(path,process):
        deadline = time.monotonic()+8
        while not path.is_file():
            if process.poll() is not None or time.monotonic()>deadline:
                raise RuntimeError('Isolated node failed before readiness: '+path.name)
            time.sleep(.02)
    try:
        for name in names:
            run('ip','netns','add',name); created.append(name)
        for i in range(5): inside(i,'ip','link','set','lo','up')
        inside(4,'ip','link','add','bridge0','type','bridge')
        inside(4,'ip','addr','add',TRANSIT+'/24','dev','bridge0')
        inside(4,'ip','link','set','bridge0','up')
        for side in (0,1):
            host = '10.'+str(71+side)+'.0.2'
            gateway = '10.'+str(71+side)+'.0.1'
            lan, peer = 'bdl'+token+str(side), 'bdp'+token+str(side)
            run('ip','link','add',lan,'type','veth','peer','name',peer)
            run('ip','link','set',lan,'netns',names[side])
            run('ip','link','set',peer,'netns',names[side+2])
            inside(side,'ip','link','set',lan,'name','lan0')
            inside(side+2,'ip','link','set',peer,'name','lan0')
            inside(side,'ip','addr','add',host+'/24','dev','lan0')
            inside(side+2,'ip','addr','add',gateway+'/24','dev','lan0')
            inside(side,'ip','link','set','dev','lan0','up'); inside(side+2,'ip','link','set','dev','lan0','up')
            inside(side,'ip','route','add','default','via',gateway)
            wan, transit = 'bdw'+token+str(side), 'bdt'+token+str(side)
            run('ip','link','add',wan,'type','veth','peer','name',transit)
            run('ip','link','set',wan,'netns',names[side+2])
            run('ip','link','set',transit,'netns',names[4])
            inside(side+2,'ip','link','set',wan,'name','wan0')
            inside(side+2,'ip','addr','add',(A_WAN if side==0 else B_WAN)+'/24','dev','wan0')
            inside(side+2,'ip','link','set','dev','wan0','up')
            inside(4,'ip','link','set',transit,'master','bridge0')
            inside(4,'ip','link','set',transit,'up')
            inside(side+2,'sysctl','-qw','net.ipv4.ip_forward=1')
            rules = '''table inet gate {
 chain input { type filter hook input priority 0; policy drop; }
 chain forward { type filter hook forward priority 0; policy drop;
 ct state established,related counter accept
 iifname "lan0" oifname "wan0" counter accept
 counter drop
 }
 }'''
            inside(side+2,'nft','-f','-',data=rules)
        observer_process = launch(4,sys.executable,str(SCRIPT),'--internal','observer')
        time.sleep(.2)
        if observer_process.poll() is not None: raise RuntimeError('Observer startup failed')
        cases = [('baseline',False,1,1),('easy',False,args.mappings,args.probes),('hard',True,args.mappings,args.probes)]
        for label,hard,mappings,probes in cases:
            for trial in range(1 if label=='baseline' else args.rounds):
                case = folder/(label+'-'+str(trial)); case.mkdir()
                for side in (0,1):
                    wan = A_WAN if side==0 else B_WAN
                    target = f'{wan}:{low}-{high} fully-random' if side==1 or hard else f'{wan}:{STABLE_PORT}'
                    inside(side+2,'nft','delete','table','ip','nat',check=False)
                    inside(side+2,'nft','-f','-',data=f'table ip nat {{\n chain postrouting {{ type nat hook postrouting priority srcnat; oifname "wan0" ip protocol tcp counter snat to {target};\n }}\n }}\n')
                captures = [launch(i+2,sys.executable,str(SCRIPT),'--internal','capture','--config',str(case/('wan-'+str(i)+'.private.jsonl'))) for i in (0,1)]
                config = dict(folder=str(case),key=secrets.token_hex(32),session=secrets.token_hex(16),mappings=mappings,seconds=args.seconds,observerPort=OBSERVER_PORT+len(summaries))
                for side in ('a','b'): save(case/('config-'+side+'.private.json'),dict(config,role=side))
                first = launch(0,sys.executable,str(SCRIPT),'--internal','node','--config',str(case/'config-a.private.json'))
                wait_file(case/'candidate.private.json',first)
                candidate = json.loads((case/'candidate.private.json').read_text())
                assert candidate[0]==A_WAN and (low<=candidate[1]<=high if hard else candidate[1]==STABLE_PORT)
                second = launch(1,sys.executable,str(SCRIPT),'--internal','node','--config',str(case/'config-b.private.json'))
                save(case/'go.private.json',dict(start=time.monotonic()+1.0,candidate=candidate,
                     targets=secrets.SystemRandom().sample(range(low,high+1),probes)))
                for process in (first,second):
                    if process.wait(timeout=args.seconds+12): raise RuntimeError('Node execution failed')
                for process in captures:
                    process.terminate(); process.wait(timeout=3)
                results = [json.loads((case/('result-'+side+'.private.json')).read_text()) for side in ('a','b')]
                headers = [json.loads(line) for line in (case/'wan-0.private.jsonl').read_text().splitlines()]
                syns = {ip:sum(h['src']==ip and h['flags']&0x12==2 for h in headers) for ip in (A_WAN,B_WAN)}
                if not all(syns.values()): raise RuntimeError('Both active SYN directions must be observed')
                for side in (0,1): (case/('router-'+str(side)+'.nft')).write_text(inside(side+2,'nft','list','ruleset'))
                expected = -math.expm1(-mappings*probes/(args.port_space**(2 if hard else 1)))
                sources = {ip:len({h['sport'] for h in headers if h['src']==ip and h['flags']&0x12==2}) for ip in (A_WAN,B_WAN)}
                if hard and probes>1 and sources[A_WAN]<2: raise RuntimeError('Dependent random mapping was not exercised')
                summary = dict(case=label,trial=trial,portSpace=args.port_space,mappings=mappings,
                    targets=probes,modelProbabilityApprox=expected,authenticatedBothWays=all(r['successes'] for r in results),
                    successes=[len(r['successes']) for r in results],wanSyns=syns,wanSourcePorts=sources,explicitMapping=False,
                    model='two-dependent-random' if hard else 'stable-plus-dependent-random',
                    secondsPerNode=args.seconds,conwuMembership=False)
                summaries.append(summary); save(folder/'results.json',summaries)
                print(json.dumps(summary),flush=True)
        save(folder/'summary.json',dict(cases=summaries,scope='isolated TCP mechanism; reduced port range; no product integration',
            easySuccesses=sum(s['authenticatedBothWays'] for s in summaries if s['case']=='easy'),
            hardSuccesses=sum(s['authenticatedBothWays'] for s in summaries if s['case']=='hard')))
    finally:
        for child in reversed(children):
            if child.poll() is None:
                child.terminate()
                try: child.wait(timeout=3)
                except subprocess.TimeoutExpired: child.kill(); child.wait(timeout=3)
        for log in logs: log.close()
        for name in reversed(created): run('ip','netns','del',name,check=False)
        remaining = run('ip','netns','list')
        clean = all(name not in remaining for name in created) and all(p.poll() is not None for p in children)
        save(folder/'cleanup.json',dict(passed=clean,namespaces=created,allChildrenExited=all(p.poll() is not None for p in children)))
        if not clean: raise RuntimeError('Namespace cleanup failed')


if __name__=='__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--enabled',action='store_true')
    parser.add_argument('--mappings',type=int,default=64)
    parser.add_argument('--probes',type=int,default=64)
    parser.add_argument('--rounds',type=int,default=3)
    parser.add_argument('--port-space',type=int,default=1024)
    parser.add_argument('--seconds',type=float,default=3)
    parser.add_argument('--internal',choices=['observer','capture','node'])
    parser.add_argument('--config',type=Path)
    arguments = parser.parse_args()
    if arguments.internal=='observer': asyncio.run(observer())
    elif arguments.internal=='capture': capture(arguments.config)
    elif arguments.internal=='node': asyncio.run(node(json.loads(arguments.config.read_text())))
    else: isolated(arguments)
