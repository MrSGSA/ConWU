"""Isolated Windows WAN checks for the installed Mimic/TCPRAW components.

The desktop creates its own temporary gateway mapping. Two approved synthetic
networks share one native receiver; no production profile, TUN or service is
changed. Private identities travel over stdin only.
"""
import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import queue
import subprocess
import threading
import time


class Node:
    def __init__(self, command, config, output):
        self.events = queue.Queue()
        self.log = Path(output).open("w", encoding="utf-8")
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace",
                                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        def read_output():
            try:
                for line in self.process.stdout:
                    if line.startswith("{"):
                        self.events.put(json.loads(line))
            finally:
                self.events.put({"eventName": "exit"})
        def read_errors():
            for line in self.process.stderr:
                self.log.write(line)
                self.log.flush()
        self.threads = [threading.Thread(target=read_output, daemon=True), threading.Thread(target=read_errors, daemon=True)]
        for thread in self.threads:
            thread.start()
        try:
            self.process.stdin.write(json.dumps(config) + "\n")
            self.process.stdin.flush()
            self.ready = self.events.get(timeout=75)
            if self.ready.get("eventName") != "ready":
                raise RuntimeError("native node did not become ready; see " + str(output))
        except BaseException:
            self.close()
            raise

    def request(self, action, **values):
        self.process.stdin.write(json.dumps({"action": action, **values}) + "\n")
        self.process.stdin.flush()
        response = self.events.get(timeout=35)
        if response.get("eventName") == "exit":
            raise RuntimeError("native node exited; inspect its log")
        return response

    def close(self):
        try:
            if self.process.poll() is None:
                self.process.stdin.write('{"action":"stop"}\n')
                self.process.stdin.flush()
                self.process.stdin.close()
                self.process.wait(timeout=25)
        except (OSError, subprocess.TimeoutExpired):
            self.process.kill()
            self.process.wait(timeout=5)
        finally:
            for thread in self.threads:
                thread.join(timeout=2)
            self.log.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--desktop", required=True)
    parser.add_argument("--components", type=Path, default=Path("C:/Program Files/StreamLink/app/components"))
    parser.add_argument("--remote-components", default="C:/Program Files/StreamLink/app/components")
    parser.add_argument("--port", type=int, default=44784)
    parser.add_argument("--source-port", type=int, default=44785)
    parser.add_argument("--carriers", default="mimic,tcpraw")
    parser.add_argument("--rates", default="5,20,35")
    parser.add_argument("--seconds", type=int, default=3)
    parser.add_argument("--lease-seconds", type=int, default=75)
    parser.add_argument("--skip-upload", action="store_true")
    parser.add_argument("--observe-headers", action="store_true")
    parser.add_argument("--fine-pacing", action="store_true", help="Request 1 ms Windows timing only while generating the synthetic load")
    parser.add_argument("--max-loss-ratio", type=float, default=0, help="Explicit receive-loss tolerance for unreliable carriers; every loss remains reported")
    parser.add_argument("--control-only", action="store_true", help="Use the actual isolated service to test direct-code enrollment, approval and guest restart")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    components = args.components.resolve(strict=True)
    modes, rates = args.carriers.split(","), [int(value) for value in args.rates.split(",")]
    if any(mode not in ("mimic", "tcpraw", "phantun") for mode in modes) or any(rate < 1 or rate > 35 for rate in rates):
        parser.error("explicit carrier and <=35 Mbps isolated load required")
    if not 1 <= args.seconds <= 10 or not 0 <= args.lease_seconds <= 120:
        parser.error("bounded test duration required")
    if not 0 <= args.max_loss_ratio <= .01:
        parser.error("loss tolerance must be between zero and one percent")
    args.output.mkdir(parents=True, exist_ok=True)
    remote_root = "C:/ProgramData/ConWU-Transport-Validation"
    remote_exe = remote_root + "/" + binary.name
    ssh_options = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10"]
    def literal(value):
        return "'" + str(value).replace("'", "''") + "'"
    def remote_command(code):
        script = "[Console]::OutputEncoding=[Text.UTF8Encoding]::new();$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';" + code
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        return ["ssh", *ssh_options, args.desktop, "powershell", "-NoProfile", "-NonInteractive", "-OutputFormat", "Text", "-EncodedCommand", encoded]
    if not args.skip_upload:
        setup = (f"$dir={literal(remote_root)};if(Test-Path -LiteralPath $dir){{"
                 "if((Get-Item -LiteralPath $dir).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Validation directory is a link'}"
                 "}else{New-Item -ItemType Directory -Path $dir|Out-Null};"
                 f"if(Get-Process|Where-Object {{$_.Path -eq {literal(remote_exe)}}}){{throw 'Previous native node still running'}}")
        subprocess.run(remote_command(setup), check=True, capture_output=True, timeout=30)
        subprocess.run(["scp", "-C", *ssh_options, str(binary), args.desktop + ":" + remote_exe], check=True, capture_output=True, timeout=240)
    report = {"status": "Running", "scope": "Desktop host to laptop guest over each carrier's autonomous public TCP-format entry; production MeshRouter/AEAD/shared receiver, installed native binaries, synthetic memory adapters; no Moonlight or PKARR acceptance", "carriers": [], "productionProfilesModified": False, "productionServicesReplaced": False}
    def save():
        (args.output / "results.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    for mode in modes:
        folder = args.output / mode
        folder.mkdir(exist_ok=True)
        nodes, observers = [], []
        trial = {"carrier": mode, "status": "Running", "measurements": [], "reconnects": []}
        report["carriers"].append(trial)
        try:
            if args.control_only:
                trial["controlChecks"] = checks = []
                for index in range(2):
                    remote = index == 0
                    config = {"Host": remote, "Components": args.remote_components if remote else str(components), "HostIp": "0.0.0.0", "Port": args.port,
                              "Mode": mode, "Autonomous": True, "SourcePort": args.source_port, "LifetimeSeconds": 300}
                    command = remote_command(f"& {literal(remote_exe)} --control-node;exit $LASTEXITCODE") if remote else [str(binary), "--control-node"]
                    nodes.append(Node(command, config, folder / ("host.log" if remote else "guest.log")))
                host, guest = nodes
                def success(node, action, **values):
                    response = node.request(action, **values)
                    trial["lastControlResponse"] = {**response, "state": {key: value for key, value in response.get("state", {}).items()
                                                                 if key not in ("code", "verification", "candidate", "proposedIp")}}
                    save()
                    if not response.get("ok"):
                        raise RuntimeError(action + ": " + response.get("error", "service rejected operation"))
                    return response["state"]
                def verify(value, label):
                    if not value:
                        raise AssertionError(label)
                    checks.append(label)
                    save()
                success(host, "create")
                until = time.monotonic() + 45
                while True:
                    issued = host.request("invite")
                    trial["lastControlResponse"] = {**issued, "state": {key: value for key, value in issued.get("state", {}).items()
                                                               if key not in ("code", "verification", "candidate", "proposedIp")}}
                    save()
                    if issued.get("ok"):
                        break
                    if time.monotonic() >= until:
                        raise RuntimeError("autonomous host did not prepare a direct code: " + issued.get("error", "no error detail"))
                    time.sleep(.2)
                verify(len(issued["state"]["code"].replace("-", "")) == 16, "autonomous host issues a sixteen-symbol direct code")
                initial = success(guest, "join", code=issued["state"]["code"])
                verify(not initial["network"] and not initial["receivedSettings"], "unapproved guest receives no network identity or settings")
                until = time.monotonic() + 35
                while True:
                    h, g = success(host, "poll"), success(guest, "poll")
                    if len(h["verification"]) == 6 and h["verification"] == g["verification"]:
                        break
                    if time.monotonic() >= until:
                        raise RuntimeError("public native pairing did not reach matching SAS")
                    time.sleep(.2)
                verify(True, "real public carrier pairing reaches matching verification codes")
                wrong = host.request("approve", verification="000001" if h["verification"] == "000000" else "000000", candidate=h["candidate"], proposedIp=h["proposedIp"])
                verify(not wrong.get("ok"), "wrong approval verification cannot grant membership")
                time.sleep(9)
                success(host, "approve", verification=h["verification"], candidate=h["candidate"], proposedIp=h["proposedIp"])
                until = time.monotonic() + 35
                while True:
                    g, h = success(guest, "poll"), host.request("status")["state"]
                    if g["network"] and h["connected"] == g["connected"] == 1:
                        break
                    if time.monotonic() >= until:
                        raise RuntimeError("approved carrier did not establish the public route")
                    time.sleep(.2)
                verify(g["receivedSettings"] and g["protocol"] == mode + "-only", "approval imports the host configuration and exact carrier")
                saved = {key: g[key] for key in ("network", "virtualIp", "peerIp", "protocol")}
                for sender, receiver in ((host, guest), (guest, host)):
                    before = receiver.request("status")["state"]["incoming"]
                    sender.request("send")
                    until = time.monotonic() + 6
                    while receiver.request("status")["state"]["incoming"] <= before:
                        if time.monotonic() >= until:
                            raise RuntimeError("approved data packet did not arrive")
                        time.sleep(.1)
                verify(True, "approved service forwards virtual-IP packets in both directions")
                guest.request("restart")
                until = time.monotonic() + 35
                while True:
                    restored = guest.request("status")["state"]
                    if restored["connected"] == 1:
                        break
                    if time.monotonic() >= until:
                        raise RuntimeError("paired guest did not recover after restart")
                    time.sleep(.2)
                verify(all(restored[key] == value for key, value in saved.items()), "guest restart preserves identity, virtual IPs and carrier without pairing again")
                trial["status"] = "Pass"
                continue
            identities = json.loads(subprocess.run([str(binary), "--identities", mode], check=True, capture_output=True, text=True, encoding="utf-8", timeout=20).stdout)
            host = Node(remote_command(f"& {literal(remote_exe)} --node;exit $LASTEXITCODE"),
                        {"Host": True, "Meshes": identities["owners"], "Components": args.remote_components, "HostIp": "0.0.0.0", "Port": args.port, "Autonomous": True, "SourcePort": args.source_port, "LifetimeSeconds": 300}, folder / "host.log")
            nodes.append(host)
            began = time.monotonic()
            address, port = host.ready["endpoint"].rsplit(":", 1)
            if not ipaddress.ip_address(address).is_global:
                raise RuntimeError("autonomous candidate is not a public IPv4 endpoint")
            trial["entry"] = host.ready["endpoint"]
            trial["initialMapping"] = host.ready["status"]["mapping"]
            if args.observe_headers:
                script = Path(__file__).with_name("Observe-CarrierHeaders.py")
                encoded = base64.b64encode(script.read_bytes()).decode("ascii")
                helper = trial["initialMapping"]["helper"].rsplit(":", 1)[0]
                observers.append(Node(remote_command("python -u -c " + literal("import base64;exec(base64.b64decode('" + encoded + "'))")),
                                      {"Address": helper, "Port": args.port, "Outbound": True, "Dll": args.remote_components + "/WinDivert.dll"}, folder / "host-headers.log"))
                observers.append(Node(["python", str(script)], {"Address": address, "Port": int(port), "Dll": str(components / "WinDivert.dll")}, folder / "guest-headers.log"))
            guest = Node([str(binary), "--node"],
                         {"Host": False, "Meshes": identities["guests"], "Components": str(components), "HostIp": address, "Port": int(port), "LifetimeSeconds": 300}, folder / "guest.log")
            nodes.append(guest)
            def states():
                return [node.request("status")["status"] for node in nodes]
            def healthy():
                until = time.monotonic() + 25
                while time.monotonic() < until:
                    current = states()
                    if all(all(network["healthy"] for network in state["networks"]) for state in current):
                        return current
                    trial["lastStates"] = current
                    time.sleep(.2)
                raise RuntimeError("authenticated native routes did not become healthy")
            connected = healthy()
            trial["connected"] = connected
            host_pids = connected[0]["nativePids"]
            if connected[0]["serverStarts"] != 1 or len(host_pids) != 1:
                raise AssertionError("two networks did not share exactly one native host")
            print(json.dumps({"carrier": mode, "event": "connected", "entry": trial["entry"], "networks": 2}), flush=True)
            def measure(sender, index, mbps, seconds):
                receiver = nodes[1 - sender]
                receiver.request("reset")
                for observer in observers:
                    observer.request("reset")
                measured = nodes[sender].request("send", index=index, mbps=mbps, seconds=seconds, finePacing=args.fine_pacing)
                until = time.monotonic() + 4
                while True:
                    incoming = receiver.request("status")["status"]
                    stats = incoming["networks"][index]["adapter"]
                    if stats["unique"] >= measured["sent"] or time.monotonic() >= until:
                        break
                    time.sleep(.1)
                row = {"sender": "desktop" if sender == 0 else "laptop", "network": index, "targetMbps": mbps, "finePacing": args.fine_pacing,
                       "sent": measured["sent"], "sourceRejected": measured["rejected"], "seconds": measured["seconds"], "sendingMbps": measured["virtualIpMbps"],
                       **stats, "otherNetworkReceived": incoming["networks"][1 - index]["adapter"]["received"]}
                if observers:
                    row["headerObservations"] = [observer.request("status")["stats"] for observer in observers]
                row["lossRatio"] = max(0, row["sent"] - row["unique"]) / max(1, row["sent"])
                row["allowedLossRatio"] = args.max_loss_ratio
                row["status"] = "Pass" if row["sent"] > 0 and row["lossRatio"] <= args.max_loss_ratio and not any(row[name] for name in ("sourceRejected", "invalid", "duplicates", "otherNetworkReceived")) and row["sendingMbps"] >= mbps * .9 else "Fail"
                trial["measurements"].append(row)
                save()
                print(json.dumps({"carrier": mode, **row}), flush=True)
                if row["status"] != "Pass":
                    trial["lastStates"] = states()
                    raise AssertionError("datagram delivery, isolation or sending budget failed")
            for rate in rates:
                for sender in (0, 1):
                    for index in (0, 1):
                        measure(sender, index, rate, args.seconds)
            for index in range(3):
                guest.request("pause", index=0)
                guest.request("resume", index=0)
                recovered = healthy()
                if recovered[0]["nativePids"] != host_pids:
                    raise AssertionError("guest reconnect replaced the shared host")
                trial["reconnects"].append({"attempt": index + 1, "healthy": True, "sharedHostUnchanged": True})
                measure(0, 0, 5, 1)
                measure(1, 1, 5, 1)
            while time.monotonic() - began < args.lease_seconds:
                healthy()
                time.sleep(min(2, max(.05, args.lease_seconds - (time.monotonic() - began))))
            trial["afterMaintenance"] = healthy()
            if trial["afterMaintenance"][0]["nativePids"] != host_pids:
                raise AssertionError("mapping maintenance replaced the shared receiver")
            measure(0, 1, 5, 2)
            measure(1, 0, 5, 2)
            trial["elapsedSeconds"] = time.monotonic() - began
            trial["status"] = "Pass"
        except Exception as error:
            trial["status"] = "Fail"
            trial["error"] = type(error).__name__ + ": " + str(error)
        finally:
            for node in reversed(nodes):
                node.close()
            for observer in reversed(observers):
                observer.close()
            trial["nodeExitCodes"] = [node.process.returncode for node in nodes]
            trial["resourcesReleased"] = len(nodes) == 2 and all(node.process.returncode == 0 for node in nodes)
            if not trial["resourcesReleased"]:
                trial["status"] = "Fail"
            save()
            print(json.dumps({"carrier": mode, "status": trial["status"], "error": trial.get("error", "")}), flush=True)
    report["status"] = "Pass" if all(trial["status"] == "Pass" for trial in report["carriers"]) else "Fail"
    report["nativeComponentSha256"] = hashlib.sha256((components / "conwu-raw.exe").read_bytes()).hexdigest()
    save()
    if report["status"] != "Pass":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
