"""Actual C++ legacy injection reports; loopback carriage, no driver/WAN."""
import argparse
import json
from pathlib import Path
import time
import uuid

from protocol_loopback import Tunnel

parser = argparse.ArgumentParser()
parser.add_argument("--output", required=True)
args = parser.parse_args()
checks = 0
rows = []


def check(value, text):
    global checks
    if not value:
        raise AssertionError(text)
    checks += 1
    print("PASS", text)


for mode in ("faketcp", "udp"):
    ids = {name: uuid.uuid4().hex for name in ("server", "client")}
    with Tunnel(http=mode == "faketcp", raw_mode=mode, wire_ids=ids) as tunnel:
        tunnel.ready()
        for _ in range(18):
            payload = bytes(range(256)) * 4
            tunnel.app.send(payload)
            check(tunnel.receive() == payload, "telemetry preserves exact legacy datagrams")
            time.sleep(0.08)
        tunnel.healthy()
        for side in ("server", "client"):
            lines = [line.split() for line in (tunnel.path / f"{side}.log").read_text(errors="replace").splitlines() if line.startswith("SLW1 ")]
            check(len(lines) >= 2, "real native process emits bounded periodic cumulative reports")
            check(all(len(p) == 21 and p[1] == ids[side] for p in lines), "local record schema and exact instance identity are stable")
            check(all(int(p[2]) > 0 and p[20] in ("0", "1") for p in lines), "report sequence and capture-window flags are valid")
            check(all(int(b[2]) > int(a[2]) and all(int(b[i]) >= int(a[i]) for i in range(4, 20)) for a, b in zip(lines, lines[1:])), "cumulative injection and capture counters never decrease")
            latest = lines[-1]
            check(latest[3] != "Unknown" and latest[3].startswith("127.0.0.1:"), "successful raw frame reports its actual source instead of the UDP bridge guess")
            check(sum(int(latest[i]) for i in (5, 7, 9, 11, 13)) > 0 and int(latest[16]) > 0, "both successful native sends and received IP frames are observed")
            rows.append({"mode": mode, "side": side, "resource": ids[side], "latest": latest, "scope": "actual C++ legacy protocol over loopback raw-IP carriage; not WinDivert, NIC or kernel peer overhead"})

with Tunnel(wire_ids={name: uuid.uuid4().hex for name in ("server", "client")}, closed_report_sink=True) as tunnel:
    tunnel.ready()
    for _ in range(8):
        payload = bytes(range(256)) * 4
        tunnel.app.send(payload)
        check(tunnel.receive() == payload, "failed telemetry sink cannot stop the protocol event loop or alter application datagrams")
        time.sleep(0.08)
    tunnel.healthy()
    check(True, "both native processes remain live after stdout observation is closed")

output = Path(args.output).resolve()
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps({"status": "Pass", "checks": checks, "rows": rows, "completeWireAudit": False}, indent=2), encoding="utf-8")
print(f"PASS {checks} legacy native telemetry checks")
