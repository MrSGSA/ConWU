"""Isolated TCP/TLS comparison: desktop host, laptop client. Keys use stdin only."""
import argparse
import base64
import json
import os
from pathlib import Path
import queue
import secrets
import subprocess
import threading
import time


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--desktop", default="")
    p.add_argument("--jump", default="")
    p.add_argument("--endpoint", default="")
    p.add_argument("--path-label", default="user-provided desktop endpoint")
    p.add_argument("--port", type=int, default=48443)
    p.add_argument("--mbps", default="20,50,100,150")
    p.add_argument("--seconds", type=int, default=8)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--skip-upload", action="store_true")
    p.add_argument("--autonomous", action="store_true")
    p.add_argument("--local", action="store_true")
    p.add_argument("--in-flight", type=int, default=512)
    a = p.parse_args()
    if not a.local and (not a.desktop or not a.autonomous and not a.endpoint):
        p.error("remote trials require --desktop and --endpoint (or --autonomous)")
    binary = a.binary.resolve(strict=True)
    a.output.mkdir(parents=True, exist_ok=True)
    # This fixed, task-specific directory never contains production profiles.
    remote_root = r"C:\ProgramData\ConWU-Transport-Validation"
    remote_exe = remote_root + "\\" + binary.name
    options = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=15"]
    if a.jump:
        options += ["-J", a.jump]

    def ssh(script, **kwargs):
        prefix = "[Console]::OutputEncoding=[Text.UTF8Encoding]::new();$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"
        encoded = base64.b64encode((prefix + script).encode("utf-16-le")).decode("ascii")
        return subprocess.Popen(["ssh", *options, a.desktop, "pwsh", "-NoProfile", "-EncodedCommand", encoded], **kwargs)

    if not a.skip_upload and not a.local:
        script = (f"$dir='{remote_root}';if(Test-Path -LiteralPath $dir){{"
                  "if((Get-Item -LiteralPath $dir).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Validation directory is a link'}"
                  "}else{New-Item -ItemType Directory -Path $dir|Out-Null};"
                  f"if(Get-Process|Where-Object {{$_.Path -eq '{remote_exe}'}}){{throw 'Previous test is still running'}}")
        control = ssh(script, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = control.communicate(timeout=45)
        if control.returncode:
            raise RuntimeError("Desktop validation directory could not be prepared: " + (out + err).decode("utf-8", errors="replace")[-1400:])
        copy = subprocess.run(["scp", "-C", *options, str(binary), a.desktop + ":" + remote_root.replace("\\", "/") + "/" + binary.name], capture_output=True, timeout=240)
        if copy.returncode:
            raise RuntimeError("Test binary upload failed: " + copy.stderr.decode("utf-8", errors="replace")[-1000:])

    results = []
    for mode in ("tcp", "https"):
        key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        config = {"Mode": mode, "Key": key, "Port": a.port, "Firewall": not a.local, "LifetimeSeconds": 240, "Autonomous": a.autonomous, "MaxInFlight": a.in_flight}
        pipes = dict(stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
        server = subprocess.Popen([str(binary), "serve"], **pipes, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0) if a.local else ssh(f"& '{remote_exe}' serve;exit $LASTEXITCODE", **pipes)
        events = queue.Queue()
        lines, stderr = [], []

        def read_server():
            for line in server.stdout:
                line = line.strip()
                lines.append(line)
                if line.startswith("CONWU_READY "):
                    events.put(json.loads(line.removeprefix("CONWU_READY ")))
            events.put(None)

        def read_errors():
            for line in server.stderr:
                stderr.append(line.strip())

        threading.Thread(target=read_server, daemon=True).start()
        threading.Thread(target=read_errors, daemon=True).start()
        try:
            server.stdin.write(json.dumps(config) + "\n")
            server.stdin.flush()
            ready = events.get(timeout=60)
            if ready is None:
                raise RuntimeError("Desktop listener exited: " + "\n".join(lines + stderr)[-2000:])
            print(json.dumps({"event": "local-ready" if a.local else "desktop-ready", "mode": mode, "desktop": a.desktop, "port": a.port}), flush=True)
            for rate in [int(value) for value in a.mbps.split(",")]:
                target = ready["endpoint"] if a.autonomous else ("127.0.0.1" if a.local else a.endpoint) + ":" + str(a.port)
                config.update({"Endpoint": target, "Pin": ready["pin"], "Mbps": rate, "Seconds": a.seconds, "Firewall": False})
                completed = subprocess.run([str(binary), "bench"], input=json.dumps(config) + "\n", capture_output=True, encoding="utf-8", errors="replace", timeout=a.seconds + 35, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
                result = next((json.loads(line.removeprefix("CONWU_BENCH_RESULT ")) for line in completed.stdout.splitlines() if line.startswith("CONWU_BENCH_RESULT ")), None)
                if result is None:
                    result = {"status": "Fail", "mode": mode, "targetMbps": rate, "error": (completed.stdout + completed.stderr)[-2000:]}
                result.update({"host": "local" if a.local else a.desktop, "endpoint": target, "path": "desktop TCP STUN candidate" if a.autonomous else "loopback" if a.local else a.path_label})
                results.append(result)
                (a.output / ("loopback-results.json" if a.local else "desktop-results.json")).write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
                print(json.dumps(result, ensure_ascii=False), flush=True)
                if result["status"] != "Pass":
                    break
                time.sleep(.5)
        finally:
            if server.poll() is None:
                try:
                    server.stdin.write("stop\n")
                    server.stdin.flush()
                    server.wait(timeout=20)
                except (BrokenPipeError, subprocess.TimeoutExpired):
                    # Host also has an independent bounded lifetime.
                    server.terminate()
            (a.output / (mode + "-host.log")).write_text("\n".join(lines + stderr), encoding="utf-8")
            key = None
    if any(result["status"] != "Pass" for result in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
