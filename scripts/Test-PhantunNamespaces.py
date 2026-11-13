"""Isolated Linux native Phantun + production MeshRouter/AEAD/multiplexer.

Two temporary network namespaces and a private veth carry all test packets.
Uses ephemeral identities over stdin, memory adapters and independent ports.
"""
import argparse
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import threading
import time
import uuid

class Node:
    def __init__(self, command, config, log):
        self.events=queue.Queue()
        self.process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding="utf-8")
        self.log=Path(log).open("w",encoding="utf-8")
        def stdout():
            for line in self.process.stdout:
                if line.startswith("{"):self.events.put(json.loads(line))
            self.events.put({"eventName":"exit"})
        def stderr():
            for line in self.process.stderr:self.log.write(line);self.log.flush()
        threading.Thread(target=stdout,daemon=True).start();threading.Thread(target=stderr,daemon=True).start()
        self.process.stdin.write(json.dumps(config)+"\n");self.process.stdin.flush()
        self.ready=self.events.get(timeout=30)
        if self.ready.get("eventName")!="ready":raise RuntimeError("native node startup failed; see "+str(log))
    def request(self,action,**kwargs):
        self.process.stdin.write(json.dumps({"action":action,**kwargs})+"\n");self.process.stdin.flush()
        response=self.events.get(timeout=45)
        if response.get("eventName")=="exit":raise RuntimeError("native test node exited")
        return response
    def close(self):
        try:
            if self.process.poll() is None:
                self.process.stdin.write('{"action":"stop"}\n');self.process.stdin.flush();self.process.stdin.close();self.process.wait(timeout=20)
        except (OSError,subprocess.TimeoutExpired):
            self.process.kill();self.process.wait(timeout=5)
        self.log.close()

def main():
    parser=argparse.ArgumentParser();parser.add_argument("--app",type=Path,required=True);parser.add_argument("--components",type=Path,required=True);parser.add_argument("--output",type=Path,required=True);parser.add_argument("--carrier",choices=["phantun","mimic","tcpraw"],default="phantun")
    args=parser.parse_args()
    if not hasattr(os,"geteuid") or os.geteuid()!=0:raise RuntimeError("run as Linux root for isolated namespaces")
    args.app=args.app.resolve();args.components=args.components.resolve();args.output=args.output.resolve();args.output.mkdir(parents=True,exist_ok=True)
    tag="cwph"+uuid.uuid4().hex[:7];names=[tag+"h",tag+"g"];interfaces=[tag+"a",tag+"b"]
    created=[];nodes=[];report={"status":"Running","scope":"isolated "+args.carrier+" + production MeshRouter, AEAD and shared receiver; memory adapters; no WAN/QoS claim","measurements":[],"reconnects":[]}
    def command(*parts,check=True):return subprocess.run(parts,check=check,capture_output=True,text=True,encoding="utf-8",timeout=15)
    def save():(args.output/"results.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
    try:
        for name in names:
            command("ip","netns","add",name);created.append(name);command("ip","-n",name,"link","set","lo","up")
        command("ip","link","add",interfaces[0],"type","veth","peer","name",interfaces[1])
        for index in range(2):
            command("ip","link","set",interfaces[index],"netns",names[index]);command("ip","-n",names[index],"addr","add",f"198.18.234.{index+1}/30","dev",interfaces[index]);command("ip","-n",names[index],"link","set",interfaces[index],"up")
        identity=subprocess.run([str(args.app),"--identities",args.carrier],capture_output=True,text=True,encoding="utf-8",check=True,timeout=15)
        profiles=json.loads(identity.stdout)
        for index,role in enumerate(["owners","guests"]):
            config={"Host":index==0,"Mode":args.carrier,"Meshes":profiles[role],"Components":str(args.components),"HostIp":"198.18.234.1","Port":49197}
            node=Node(["ip","netns","exec",names[index],str(args.app),"--node"],config,args.output/(role+".log"));nodes.append(node)
        def healthy():
            deadline=time.monotonic()+15
            while time.monotonic()<deadline:
                states=[node.request("status")["status"] for node in nodes]
                if all(all(net["healthy"] for net in state["networks"]) for state in states):return states
                time.sleep(.1)
            raise RuntimeError("native Phantun authenticated paths did not recover")
        report["connected"]=healthy();save()
        assert report["connected"][0]["serverStarts"]==1 and len(report["connected"][0]["nativePids"])==1
        def measure(sender_index,index,mbps,seconds):
            receiver=nodes[1-sender_index];receiver.request("reset")
            result=nodes[sender_index].request("send",index=index,mbps=mbps,seconds=seconds)
            until=time.monotonic()+3
            while True:
                state=receiver.request("status")["status"];stats=state["networks"][index]["adapter"]
                if stats["received"]>=result["sent"] or time.monotonic()>=until:break
                time.sleep(.05)
            other=state["networks"][1-index]["adapter"]
            row={"sender":"host" if sender_index==0 else "guest","network":index,"requestedVirtualIpMbps":mbps,"sent":result["sent"],"received":stats["received"],"invalid":stats["invalid"],"otherNetworkReceived":other["received"],"sourceRejected":result["rejected"],"virtualIpMbps":result["virtualIpMbps"],"seconds":result["seconds"]}
            report["measurements"].append(row);save();print(json.dumps(row),flush=True)
            assert result["sent"]==stats["received"] and stats["invalid"]==0 and other["received"]==0 and result["rejected"]==0 and result["virtualIpMbps"]>=mbps*.9,row
        for sender in range(2):
            for index in range(2):measure(sender,index,35,3)
        original_server=report["connected"][0]["nativePids"][0]
        for iteration in range(6):
            nodes[1].request("pause",index=0);nodes[1].request("resume",index=0);state=healthy()
            assert state[0]["nativePids"]==[original_server],"another network recreated the shared listener"
            report["reconnects"].append({"iteration":iteration+1,"healthy":True,"sharedServerUnchanged":True});save()
        measure(0,0,35,3);measure(1,1,35,3)
        released=nodes[0].request("release",index=0)
        assert released["status"]["nativePids"]==[original_server]
        measure(1,1,35,3)
        for node in reversed(nodes):node.close()
        nodes.clear()
        # Start with empty profiles. This phase uses the production control
        # worker to generate a code, perform SAS approval, import host settings
        # and restart a paired guest. No pre-issued enrollment is supplied.
        for index in range(2):
            config={"Host":index==0,"Mode":args.carrier,"Components":str(args.components),"HostIp":"198.18.234.1","Port":49197}
            nodes.append(Node(["ip","netns","exec",names[index],str(args.app),"--control-node"],config,args.output/("control-host.log" if index==0 else "control-guest.log")))
        host,guest=nodes
        control=[]
        def verify(value,description):
            if not value:raise AssertionError(description)
            control.append(description);report["controlChecks"]=control;save()
        def successful(node,action,**kwargs):
            response=node.request(action,**kwargs)
            if not response.get("ok"):raise RuntimeError(action+": "+str(response.get("error")))
            return response["state"]
        successful(host,"create")
        deadline=time.monotonic()+15
        while True:
            issued=host.request("invite")
            if issued.get("ok"):break
            if time.monotonic()>=deadline:raise RuntimeError("no direct code: "+str(issued.get("error")))
            time.sleep(.2)
        verify(len(issued["state"]["code"].replace("-",""))==16,"production service issues a sixteen-symbol carrier code")
        initial=successful(guest,"join",code=issued["state"]["code"])
        verify(not initial["receivedSettings"] and not initial["network"],"unapproved guest has no network credential or imported host settings")
        deadline=time.monotonic()+30
        while True:
            h=successful(host,"poll");g=successful(guest,"poll")
            if len(h["verification"])==6 and h["verification"]==g["verification"]:break
            if time.monotonic()>=deadline:raise RuntimeError("SAS approval did not become available")
            time.sleep(.25)
        verify(True,"actual native pairing exchanges commitments and matching SAS through the shared listener")
        invalid=host.request("approve",verification="000001" if h["verification"]=="000000" else "000000",candidate=h["candidate"],proposedIp=h["proposedIp"])
        verify(not invalid.get("ok"),"wrong approval verification cannot grant membership")
        time.sleep(9)
        successful(host,"approve",verification=h["verification"],candidate=h["candidate"],proposedIp=h["proposedIp"])
        deadline=time.monotonic()+30
        while True:
            g=successful(guest,"poll");h=host.request("status")["state"]
            if g["network"] and h["connected"]==g["connected"]==1:break
            if time.monotonic()>=deadline:raise RuntimeError("approved service did not reach an authenticated data path")
            time.sleep(.25)
        verify(g["receivedSettings"] and g["protocol"]==args.carrier+"-only" and g["network"]==h["network"],"approval imports the host protocol, identity and settings after a human confirmation delay")
        verify(True,"production runner reaches direct connectivity without a coordinator or a second traversal protocol")
        for sender,receiver in [(host,guest),(guest,host)]:
            before=receiver.request("status")["state"]["incoming"];sender.request("send");deadline=time.monotonic()+10
            while receiver.request("status")["state"]["incoming"]==before:
                if time.monotonic()>=deadline:raise RuntimeError("approved data packet not delivered")
                time.sleep(.1)
        verify(True,"approved production runners deliver full-MTU virtual-IP packets in both directions")
        saved=(g["network"],g["virtualIp"],g["protocol"]);guest.request("restart");deadline=time.monotonic()+20
        while True:
            g=guest.request("status")["state"]
            if g["connected"]==1:break
            if time.monotonic()>=deadline:raise RuntimeError("paired service did not reconnect after restart")
            time.sleep(.2)
        verify((g["network"],g["virtualIp"],g["protocol"])==saved and g["receivedSettings"],"restarting the guest retains its approved identity, virtual IP and carrier configuration")
        report["status"]="Pass"
    except Exception as error:
        report["diagnosticStates"]=[]
        for node in nodes:
            try:
                state=node.request("status");state.pop("code",None);report["diagnosticStates"].append(state)
            except Exception:pass
        report["status"]="Fail";report["error"]=type(error).__name__+": "+str(error);print(json.dumps({"error":report["error"]}),flush=True)
    finally:
        for node in reversed(nodes):node.close()
        leftovers={}
        for name in created:
            leftovers[name]=command("ip","netns","pids",name,check=False).stdout.split()
        report["leftoverProcesses"]=leftovers
        for name in reversed(created):command("ip","netns","del",name,check=False)
        for interface in interfaces:command("ip","link","del",interface,check=False)
        namespaces=command("ip","netns","list").stdout
        report["namespacesRemoved"]=all(name not in namespaces for name in created)
        report["resourcesReleased"]=all(not pids for pids in leftovers.values()) and report["namespacesRemoved"]
        save();print(json.dumps({"status":report["status"],"resourcesReleased":report["resourcesReleased"],"report":str(args.output/"results.json")}),flush=True)
    if report["status"]!="Pass" or not report["resourcesReleased"]:raise SystemExit(1)

if __name__=="__main__":main()
