#!/usr/bin/env python3
"""Run inside an isolated Linux network namespace, using the actual published host."""
import json
import os
from pathlib import Path
import socket
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

binary = str(Path(sys.argv[1]).resolve())
root = Path(tempfile.mkdtemp(prefix="streamlink-unified-"))
env = dict(os.environ, STREAMLINK_PROFILE_ROOT=str(root))
checks = []

def check(condition, description):
    if not condition:
        raise AssertionError(description)
    checks.append(description)

def cli(*args):
    run = subprocess.run([binary, *args], env=env, text=True, capture_output=True, timeout=35)
    if run.returncode:
        raise AssertionError(run.stderr.strip() or run.stdout.strip())
    return json.loads(run.stdout)

def wait(predicate, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.2)
    raise AssertionError("expected state did not arrive")

def apply(value):
    file = root / "input.json"
    file.write_text(json.dumps(value), encoding="utf-8")
    return cli("config", "apply", str(file))

with socket.socket() as port:
    port.bind(("127.0.0.1", 0))
    selected_port = port.getsockname()[1]
log = open(root / "host.log", "w")
host = subprocess.Popen([binary, "run", "--no-web"], env=env, stdout=log, stderr=subprocess.STDOUT)
try:
    wait(lambda: (root / "control.sock").exists())
    state = cli("status")
    check(state["ServiceReady"] and state["Platform"] == "linux", "real Linux service and authenticated CLI are ready")
    check(not state["Coordinator"]["Enabled"] and not state["NetworkEnabled"], "roles start disabled without inventing membership")
    apply({"DeviceName": "linux-unified-test", "Network": {"Coordinator": {"Enabled": True, "ListenUrl": f"http://127.0.0.1:{selected_port}"}}})
    wait(lambda: cli("status")["Coordinator"]["Running"])
    with urllib.request.urlopen(f"http://127.0.0.1:{selected_port}/health", timeout=3) as response:
        health = json.load(response)
    check(health["meshGovernance"] == 1 and health["integratedCoordinator"] == 1, "integrated host exposes production coordination routes")
    check(cli("status")["DeviceName"] == "linux-unified-test", "settings saved through the shared mutation path")
    check((root.stat().st_mode & 0o777) == 0o700 and ((root / "profile.json").stat().st_mode & 0o777) == 0o600, "Linux profile and socket directory are private")
    apply({"Network": {"Coordinator": {"Enabled": False}}})
    wait(lambda: not cli("status")["Coordinator"]["Running"])
    check(cli("status")["DeviceName"] == "linux-unified-test", "changing coordinator role preserves unrelated settings")
    host.terminate()
    check(host.wait(timeout=20) == 0, "SIGTERM stops the actual daemon cleanly")
    check(not (root / "control.sock").exists(), "shutdown removes the owned control socket")
    host = subprocess.Popen([binary, "run", "--no-web"], env=env, stdout=log, stderr=subprocess.STDOUT)
    wait(lambda: (root / "control.sock").exists())
    check(cli("status")["DeviceName"] == "linux-unified-test", "restart preserves saved settings")
    print(json.dumps({"status": "Pass", "checks": checks, "evidence": str(root)}, ensure_ascii=False))
finally:
    if host.poll() is None:
        host.terminate()
        try:
            host.wait(timeout=20)
        except subprocess.TimeoutExpired:
            host.kill()
            host.wait()
    log.close()
    evidence=Path(__file__).resolve().parents[1]/'artifacts'/'unified-linux-host'/root.name
    evidence.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(root/'host.log',evidence/'host.log')
