"""Full enrollment/recovery on a Windows/WSL virtual LAN, with memory adapters.

No installed service, production profile, router or physical adapter is changed.
Invitations stay in process memory; reports contain no pairing credentials.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--distro",default="ArchLinux")
    parser.add_argument("--standard-wsl-mtu",action="store_true",help="temporarily use MTU 1500 on development WSL eth0 and restore it")
    parser.add_argument("--hosts",nargs="+",choices=["windows","linux"],default=["windows","linux"])
    parser.add_argument("--modes",nargs="+",default=["faketcp","phantun","mimic","tcpraw","tcp","https"])
    args=parser.parse_args()
    root=Path(__file__).resolve().parent.parent
    args.output=args.output.resolve();args.output.mkdir(parents=True,exist_ok=True)
    spec=importlib.util.spec_from_file_location("pair_lab",root/"scripts/Test-TcpAssistNamespaces.py")
    lab=importlib.util.module_from_spec(spec);spec.loader.exec_module(lab)
    wsl=["wsl","-d",args.distro,"-u","root","--"]
    def run(*command):
        return subprocess.run(command,check=True,capture_output=True,text=True,encoding="utf-8",timeout=20).stdout
    linux_ip=json.loads(run(*wsl,"ip","-j","-4","address","show","dev","eth0"))[0]["addr_info"][0]["local"]
    windows_ip=json.loads(run(*wsl,"ip","-j","-4","route","show","default"))[0]["gateway"]
    linux_root=run(*wsl,"wslpath","-a",root.as_posix()).strip()
    original_mtu=json.loads(run(*wsl,"ip","-j","link","show","dev","eth0"))[0]["mtu"]
    mtu_changed=False
    apps={"windows":[str(root/"tests/ConWU.PhantunTests/bin/Release/net10.0/ConWU.PhantunTests.exe")],
          "linux":[*wsl,linux_root+"/out/tcp-assist-lab/linux/ConWU.PhantunTests"]}
    components={"windows":str(root/"out/raw-carrier-lab/components"),"linux":linux_root+"/out/tcp-assist-lab/components-linux"}
    report={"status":"Running","scope":"Windows/WSL virtual LAN; real enrollment, native carriers and AEAD; no WAN or strict-NAT claim","cases":[]}
    def save():
        (args.output/"results.json").write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8")
    try:
        if args.standard_wsl_mtu and original_mtu!=1500:
            run(*wsl,"ip","link","set","dev","eth0","mtu","1500");mtu_changed=True
        report["wslMtu"]={"original":original_mtu,"test":1500 if mtu_changed else original_mtu}
        for host_os in args.hosts:
            for mode in args.modes:
                row={"host":host_os,"mode":mode,"checks":[]};report["cases"].append(row);save()
                nodes=[]
                try:
                    for is_host in (True,False):
                        platform=host_os if is_host else ("windows" if host_os=="linux" else "linux")
                        config={"Host":is_host,"Components":components[platform],"HostIp":windows_ip if host_os=="windows" else linux_ip,
                                "Port":49420,"Mode":mode,"Autonomous":False,"LifetimeSeconds":300,"NativeDiagnostics":True}
                        nodes.append(lab.Actor([*apps[platform],"--control-node"],args.output/(host_os+"-"+mode+("-host" if is_host else "-guest")+".log"),config))
                    lab.exercise_pair(*nodes,False,row,save)
                    row["status"]="Pass";save();print(json.dumps(row),flush=True)
                except Exception as error:
                    row["error"]=str(error);row["lastStates"]=[]
                    for node in nodes:
                        try:
                            state=node.request("status")["state"]
                            row["lastStates"].append({k:v for k,v in state.items() if k not in ("code","verification","candidate","proposedIp")})
                        except Exception:pass
                    raise
                finally:
                    for node in reversed(nodes):node.close()
        report["status"]="Pass"
    except Exception as error:
        report["status"]="Fail";report["error"]=str(error);raise
    finally:
        if mtu_changed:run(*wsl,"ip","link","set","dev","eth0","mtu",str(original_mtu))
        report["wslMtuRestored"]=json.loads(run(*wsl,"ip","-j","link","show","dev","eth0"))[0]["mtu"]==original_mtu
        save()


if __name__=="__main__":main()
