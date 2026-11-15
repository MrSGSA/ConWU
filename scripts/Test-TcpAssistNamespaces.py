"""Real six-carrier assistance/approval/AEAD in disposable Linux namespaces.

No WAN, physical adapter, installed service, router or default route is used.
Synthetic globally eligible addresses stay on a private namespace veth.
Ordinary outbound paths are disabled in the actors to exercise assistance.
"""
import argparse
import json
import os
from pathlib import Path
import queue
import subprocess
import threading
import time
import uuid


class Actor:
    def __init__(self, command, log, config=None):
        self.events = queue.Queue()
        self.log = Path(log).open("w", encoding="utf-8")
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, encoding="utf-8")
        def output():
            for line in self.process.stdout:
                if line.startswith("{"):
                    self.events.put(json.loads(line))
            self.events.put({"eventName": "exit"})
        def errors():
            for line in self.process.stderr:
                self.log.write(line)
                self.log.flush()
        threading.Thread(target=output, daemon=True).start()
        threading.Thread(target=errors, daemon=True).start()
        if config is not None:
            self.process.stdin.write(json.dumps(config)+"\n")
            self.process.stdin.flush()
        self.ready = self.events.get(timeout=30)
        if self.ready.get("eventName") != "ready":
            raise RuntimeError("actor startup failed; inspect "+str(log))

    def request(self, action, **values):
        self.process.stdin.write(json.dumps({"action": action, **values})+"\n")
        self.process.stdin.flush()
        value = self.events.get(timeout=90)
        if value.get("eventName") == "exit" or value.get("ok") is False:
            raise RuntimeError(value.get("eventName", "actor")+": "+str(value.get("error", "actor exited")))
        return value

    def close(self):
        try:
            if self.process.poll() is None:
                self.process.stdin.write('{"action":"stop"}\n')
                self.process.stdin.flush()
                self.process.stdin.close()
                self.process.wait(timeout=20)
        except (OSError, subprocess.TimeoutExpired):
            self.process.kill()
            self.process.wait(timeout=5)
        self.log.close()


def exercise_pair(host, guest, assisted, row, save):
    def record(message):
        row["checks"].append(message)
        save()
    def wait(predicate, seconds=45):
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            result=predicate()
            if result:return result
            time.sleep(.15)
        raise TimeoutError("isolated carrier condition timed out")
    def connected():
        states=[n.request("status")["state"] for n in (host,guest)]
        return all(s["connected"]==1 and s["activeAdapters"]==1 and not s["paused"] for s in states)
    def exchange():
        counts=[n.request("status")["state"]["incoming"] for n in (host,guest)]
        next_send=0
        def received():
            nonlocal next_send
            if connected() and time.monotonic()>=next_send:
                for n in (host,guest):n.request("send")
                next_send=time.monotonic()+.5
            return all(n.request("status")["state"]["incoming"]>c for n,c in zip((host,guest),counts))
        wait(received)
    host.request("create")
    code=host.request("invite")["state"]["code"]
    record("real same-port STUN and sixteen-symbol assisted invitation" if assisted else "saved reachable entry and sixteen-symbol direct invitation")
    guest.request("join",code=code)
    def sas():
        guest.request("poll")
        state=host.request("poll")["state"]
        return state if len(state["verification"])==6 else None
    pending=wait(sas)
    host.request("approve",verification=pending["verification"],candidate=pending["candidate"],proposedIp=pending["proposedIp"])
    wait(lambda:guest.request("poll")["state"]["receivedSettings"])
    record("native handshake, direct SAS approval and configuration inheritance")
    wait(connected);exchange()
    record("bidirectional authenticated virtual-IP packet delivery")
    guest.request("disconnect")
    wait(lambda:guest.request("status")["state"]["paused"])
    guest.request("reconnect");wait(connected);exchange()
    record("disconnect/reconnect retains the approved network and restores packet delivery")
    saved=[{k:n.request("status")["state"][k] for k in ("network","virtualIp","peerIp","protocol")} for n in (host,guest)]
    for restarted,label in ((guest,"guest"),(host,"host")):
        restarted.request("restart");wait(connected);exchange()
        for n,original in zip((host,guest),saved):
            state=n.request("status")["state"]
            if any(state[k]!=v for k,v in original.items()):raise AssertionError("restart changed the approved identity, IP or protocol")
        record(label+" worker/native restart and bidirectional authenticated recovery")
    if not assisted:
        if any(n.request("status")["state"]["entryProbes"]!=0 for n in (host,guest)):raise AssertionError("existing entries started autonomous preparation")
        record("existing entry never starts STUN or gateway mapping")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--components", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--strategy", choices=["assisted","entry"], default="assisted")
    parser.add_argument("--modes", nargs="+", default=["faketcp", "phantun", "mimic", "tcpraw", "tcp", "https"])
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("requires Linux root for disposable namespaces")
    args.app = args.app.resolve()
    args.components = args.components.resolve()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    tag = "cwat"+uuid.uuid4().hex[:7]
    names = [tag+"h", tag+"g"]
    interfaces = [tag+"a", tag+"b"]
    created, actors = [], []
    report = {"status": "Running", "strategy":args.strategy, "scope": "isolated native carriers, real coordination/STUN, approval and AEAD; no strict-NAT or WAN acceptance", "modes": []}
    def save():
        (args.output/"results.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    def command(*parts, check=True):
        return subprocess.run(parts, check=check, capture_output=True, text=True, timeout=20)
    def actor(index, flag, name, config=None):
        node = Actor(["ip", "netns", "exec", names[index], str(args.app), flag], args.output/(name+".log"), config)
        actors.append(node)
        return node
    try:
        for name in names:
            command("ip", "netns", "add", name)
            created.append(name)
            command("ip", "-n", name, "link", "set", "lo", "up")
        command("ip", "link", "add", interfaces[0], "type", "veth", "peer", "name", interfaces[1])
        for i in range(2):
            command("ip", "link", "set", interfaces[i], "netns", names[i])
            command("ip", "-n", names[i], "addr", "add", f"11.254.249.{i+1}/30", "dev", interfaces[i])
            command("ip", "-n", names[i], "link", "set", interfaces[i], "up")
        helper = actor(0, "--assist-helper", "helper") if args.strategy=="assisted" else None
        for mode in args.modes:
            row = {"mode": mode, "checks": []}
            report["modes"].append(row)
            save()
            assisted=args.strategy=="assisted"
            config = {"Components": str(args.components), "HostIp": "11.254.249.1", "Port": 49400,
                      "Mode": mode, "Autonomous": assisted, "LifetimeSeconds": 300,
                      "Coordinator": "https://11.254.249.1:49350/" if assisted else "", "CoordinatorPin": helper.ready["pin"] if helper else "",
                      "TcpStun": ["11.254.249.1:49350"], "AllowGatewayMapping": False, "ForceAssistance": assisted,"NativeDiagnostics": True}
            host = actor(0, "--control-node", mode+"-host", {**config, "Host": True})
            guest = actor(1, "--control-node", mode+"-guest", {**config, "Host": False})
            try:
                exercise_pair(host,guest,assisted,row,save)
                row["status"] = "Pass"
                print(json.dumps(row), flush=True)
                save()
            except Exception as error:
                row["error"]=str(error)
                row["lastStates"]=[]
                for node in (host,guest):
                    try:
                        state=node.request("status")["state"]
                        row["lastStates"].append({k:v for k,v in state.items() if k not in ("code","verification","candidate","proposedIp")})
                    except Exception:pass
                save()
                raise
            finally:
                guest.close()
                host.close()
        report["status"] = "Pass"
    except Exception as error:
        report["status"] = "Fail"
        report["error"] = str(error)
        raise
    finally:
        for item in reversed(actors):
            if item.process.poll() is None:
                item.close()
        for name in reversed(created):
            command("ip", "netns", "del", name, check=False)
        save()


if __name__ == "__main__":
    main()
