"""Windows/WSL native carrier interoperability, isolated memory adapters only.

Exercises the production MeshRouter, AEAD, shared receiver and carrier process.
No installed ConWU service/profile, router, WAN endpoint or TUN is changed.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--carrier", choices=["mimic", "tcpraw", "phantun"], required=True)
    parser.add_argument("--host", choices=["windows", "linux"], required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--distro", default="ArchLinux")
    parser.add_argument("--standard-wsl-mtu", action="store_true", help="temporarily use MTU 1500 on the development WSL eth0; always restore")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location("carrier_lab", root / "scripts/Test-PhantunNamespaces.py")
    lab = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lab)
    wsl = ["wsl", "-d", args.distro, "-u", "root", "--"]
    def run(command):
        return subprocess.run(command, check=True, capture_output=True, text=True, encoding="utf-8", timeout=20).stdout
    linux_ip = json.loads(run([*wsl, "ip", "-j", "-4", "address", "show", "dev", "eth0"]))[0]["addr_info"][0]["local"]
    windows_ip = json.loads(run([*wsl, "ip", "-j", "-4", "route", "show", "default"]))[0]["gateway"]
    linux_root = run([*wsl, "wslpath", "-a", root.as_posix()]).strip()
    win_app = ["dotnet", str(root / "tests/StreamLink.PhantunTests/bin/Release/net10.0/StreamLink.PhantunTests.dll")]
    linux_app = [*wsl, linux_root + "/out/raw-carrier-lab/linux/StreamLink.PhantunTests"]
    identities = json.loads(run([*win_app, "--identities", args.carrier]))
    host_ip = linux_ip if args.host == "linux" else windows_ip
    nodes = []
    original_mtu = json.loads(run([*wsl, "ip", "-j", "link", "show", "dev", "eth0"]))[0]["mtu"]
    mtu_changed = False
    report = {"status": "Running", "carrier": args.carrier, "host": args.host,
              "scope": "Windows/WSL virtual LAN; synthetic memory-adapter traffic; no WAN QoS claim", "measurements": []}
    def save():
        (output / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    def healthy():
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            states = [node.request("status")["status"] for node in nodes]
            if all(all(network["healthy"] for network in state["networks"]) for state in states):
                return states
            time.sleep(.1)
        report["lastStates"] = states
        raise RuntimeError("native carrier did not establish authenticated routes")
    try:
        if args.standard_wsl_mtu and original_mtu != 1500:
            run([*wsl, "ip", "link", "set", "dev", "eth0", "mtu", "1500"])
            mtu_changed = True
        report["wslMtu"] = {"original": original_mtu, "test": 1500 if mtu_changed else original_mtu}
        for index, role in enumerate(["owners", "guests"]):
            linux = (args.host == "linux") == (index == 0)
            config = {"Host": index == 0, "Meshes": identities[role], "Mode": args.carrier,
                      "Components": linux_root + "/out/raw-carrier-lab/linux/components" if linux else str(root / "out/raw-carrier-lab/components"),
                      "HostIp": host_ip, "Port": 49275}
            nodes.append(lab.Node([*(linux_app if linux else win_app), "--node"], config, output / (role + ".log")))
        report["connected"] = healthy()
        original_server = report["connected"][0]["nativePids"]
        for sender_index in [0, 1]:
            for network in [0, 1]:
                receiver = nodes[1-sender_index]
                receiver.request("reset")
                measured = nodes[sender_index].request("send", index=network, mbps=35, seconds=3)
                deadline = time.monotonic() + 3
                while True:
                    states = receiver.request("status")["status"]["networks"]
                    stats = states[network]["adapter"]
                    if stats["received"] >= measured["sent"] or time.monotonic() >= deadline:
                        break
                    time.sleep(.05)
                row = {"sender": "host" if sender_index == 0 else "guest", "network": network, **measured,
                       "received": stats["received"], "invalid": stats["invalid"], "otherNetworkReceived": states[1-network]["adapter"]["received"]}
                report["measurements"].append(row)
                report["lastStates"] = [node.request("status")["status"] for node in nodes]
                save()
                print(json.dumps(row), flush=True)
                if row["invalid"] or row["otherNetworkReceived"] or row["rejected"] or row["received"] != row["sent"]:
                    raise AssertionError("interop datagram delivery/isolation failed")
        for _ in range(3):
            nodes[1].request("pause", index=0)
            nodes[1].request("resume", index=0)
            if healthy()[0]["nativePids"] != original_server:
                raise AssertionError("guest reconnect replaced shared host")
        report["reconnects"] = 3
        report["status"] = "Pass"
    except Exception as error:
        report["status"] = "Fail"
        report["error"] = type(error).__name__ + ": " + str(error)
    finally:
        try:
            for node in reversed(nodes):
                node.close()
        finally:
            if mtu_changed:
                run([*wsl, "ip", "link", "set", "dev", "eth0", "mtu", str(original_mtu)])
        report["wslMtuRestored"] = json.loads(run([*wsl, "ip", "-j", "link", "show", "dev", "eth0"]))[0]["mtu"] == original_mtu
        report["nodeExitCodes"] = [node.process.returncode for node in nodes]
        report["resourcesReleased"] = all(code == 0 for code in report["nodeExitCodes"])
        save()
        print(json.dumps({"status": report["status"], "report": str(output / "results.json")}), flush=True)
    if report["status"] != "Pass" or not report["resourcesReleased"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
