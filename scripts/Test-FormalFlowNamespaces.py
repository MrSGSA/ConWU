"""Bounded TCP/HTTPS flow-lane check through the complete production router."""
import argparse
import json
from pathlib import Path
import os
import subprocess
import time
import uuid
import importlib.util
_spec = importlib.util.spec_from_file_location("conwu_flow_lab", Path(__file__).with_name("Test-FlowLaneNamespaces.py"))
_lab = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_lab)
Node, configure_device = _lab.Node, _lab.configure_device


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=8)
    parser.add_argument("--rounds", type=int, default=2)
    args = parser.parse_args()
    if os.geteuid() != 0 or not 2 <= args.seconds <= 20 or not 1 <= args.rounds <= 3:
        raise ValueError("requires root and bounded duration")
    args.app = args.app.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    tag = "cwfl" + uuid.uuid4().hex[:7]
    names = [tag + "h", tag + "g"]
    devices = [tag + "a", tag + "b"]
    created, nodes = [], []
    report = {"status": "Running", "scope": "Complete production MeshRouter and shared TCP/HTTPS listener; synthetic packet adapters; isolated 50 Mbps namespaces, 5 ms per direction; no Moonlight or ISP QoS claim", "rows": []}

    def command(*parts, check=True):
        return subprocess.run(parts, check=check, capture_output=True, text=True, timeout=30)

    def ns(i, *parts):
        return command("ip", "netns", "exec", names[i], *parts)

    def save():
        (args.output / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    def udp_errors(i):
        lines = ns(i, "cat", "/proc/net/snmp").stdout.splitlines()
        for n in range(0, len(lines), 2):
            if lines[n].startswith("Udp:"):
                return dict(zip(lines[n].split()[1:], map(int, lines[n+1].split()[1:])))

    def shape(loss, seed):
        for i in range(2):
            command("ip", "netns", "exec", names[i], "tc", "qdisc", "del", "dev", devices[i], "root", check=False)
            ns(i, "tc", "qdisc", "add", "dev", devices[i], "root", "handle", "1:", "htb", "default", "10")
            ns(i, "tc", "class", "add", "dev", devices[i], "parent", "1:", "classid", "1:10", "htb", "rate", "50mbit", "ceil", "50mbit", "burst", "8192", "cburst", "8192")
            ns(i, "tc", "qdisc", "add", "dev", devices[i], "parent", "1:10", "handle", "20:", "netem", "delay", "5ms", "loss", str(loss)+"%", "limit", "1000", "seed", str(seed+i))

    try:
        for name in names:
            command("ip", "netns", "add", name); created.append(name)
        command("ip", "link", "add", devices[0], "type", "veth", "peer", "name", devices[1])
        for i in range(2):
            command("ip", "link", "set", devices[i], "netns", names[i])
            ns(i, "ip", "link", "set", "lo", "up")
            ns(i, "ip", "address", "add", "10.91.0."+str(i+1)+"/30", "dev", devices[i])
            ns(i, "ip", "link", "set", devices[i], "up")
            result = ns(i, "python3", str(Path(__file__).resolve()), "--configure-device", devices[i])
            report.setdefault("offloads", []).append(json.loads(result.stdout))
        for mode in ["tcp", "https"]:
            for loss in [0, 0.3]:
                for repeat in range(args.rounds):
                    for lanes in ([False, True] if repeat % 2 == 0 else [True, False]):
                        shape(0, 7200 + repeat*10)
                        label = f"{mode}-{loss}-{repeat}-{'lanes' if lanes else 'single'}"
                        host = Node(["ip", "netns", "exec", names[0], str(args.app), "--formal-flow-node"], {"host": True, "mode": mode, "lanes": lanes, "port": 44888}, args.output / (label+"-host.log")); nodes.append(host)
                        guest = Node(["ip", "netns", "exec", names[1], str(args.app), "--formal-flow-node"], {"host": False, "mode": mode, "lanes": lanes, "target": "10.91.0.1:44888", "mesh": host.ready["mesh"]}, args.output / (label+"-guest.log")); nodes.append(guest)
                        deadline = time.monotonic()+25
                        while True:
                            states = [node.request("reset")["peer"] for node in [host, guest]]
                            if all(s["Connected"] and (not lanes or s["StreamFlows"]["SplitActive"]) for s in states):
                                break
                            if time.monotonic() > deadline:
                                raise RuntimeError("formal path not established: "+label)
                            time.sleep(.2)
                        shape(loss, 7200 + repeat*10)
                        before = [udp_errors(i) for i in range(2)]
                        for node in [host, guest]: node.request("reset")
                        guest.request("start", mbps=35, seconds=args.seconds)
                        host.request("start", mbps=35, seconds=args.seconds)
                        time.sleep(args.seconds+2)
                        results = [node.request("finish") for node in [host, guest]]
                        after = [udp_errors(i) for i in range(2)]
                        row = {"mode": mode, "lossPercent": loss, "repeat": repeat, "lanes": lanes, "videoMbps": results[1]["stats"]["videoBytes"]*8/args.seconds/1e6, "host": results[0], "guest": results[1], "udpDelta": [{k: after[i][k]-before[i][k] for k in after[i]} for i in range(2)]}
                        report["rows"].append(row); save()
                        print(json.dumps({k: row[k] for k in ["mode", "lossPercent", "repeat", "lanes", "videoMbps"]} | {"controlP99": row["guest"]["stats"]["controlP99"], "reordered": row["guest"]["stats"]["reordered"]}), flush=True)
                        guest.close(); host.close(); nodes.clear()
        report["status"] = "Pass"
    finally:
        for node in reversed(nodes): node.close()
        for name in reversed(created): command("ip", "netns", "del", name, check=False)
        report["namespaceCleanup"] = all(name not in command("ip", "netns", "list").stdout for name in created)
        save()


if __name__ == "__main__":
    if len(__import__("sys").argv) == 3 and __import__("sys").argv[1] == "--configure-device":
        configure_device(__import__("sys").argv[2])
    else:
        main()
