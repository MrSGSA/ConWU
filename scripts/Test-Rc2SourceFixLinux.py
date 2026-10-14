#!/usr/bin/env python3
"""Offline Linux checks for RC2 source fixes; NOT .NET/Windows/driver validation."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import time


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    if output.exists():
        parser.error("Choose a new output directory; existing evidence will not be overwritten")
    output.mkdir(parents=True)
    compiler = shutil.which(os.environ.get("CXX", "g++"))
    if not compiler:
        (output / "manifest.json").write_text(json.dumps({"status": "Blocked", "reason": "C++ compiler unavailable"}))
        return 2
    env = os.environ.copy()
    env.update(CXX=compiler, ASAN_OPTIONS="detect_leaks=1", UBSAN_OPTIONS="halt_on_error=1")
    results: list[dict] = []

    def inputs() -> dict[str, str]:
        paths = [p for p in (root / "transport/udp2raw").rglob("*") if p.is_file()]
        paths += [root / "drivers/StreamLink.Tun/read_reservation.h", root / "drivers/StreamLink.Tun/driver.c",
                  root / "tests/native_tun_reservation_test.cpp", root / "tests/native_so_state_test.cpp",
                  root / "tests/native_parser_test.cpp", root / "scripts/Test-NativeParserSanitizers.sh",
                  Path(__file__).resolve()]
        return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(set(paths))}

    before = inputs()
    (output / "inputs-before.json").write_text(json.dumps(before, indent=2), encoding="utf-8")
    flags = ["-std=c++17", "-g", "-O1", "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-pthread"]
    commands = [
        ("compiler", [compiler, "--version"], 10),
        ("parser-production", ["bash", "scripts/Test-NativeParserSanitizers.sh", str(output / "parser")], 240),
        ("so-build", [compiler, *flags, "-Itransport/udp2raw", "tests/native_so_state_test.cpp", "-o", str(output / "so")], 120),
        ("so-model", [str(output / "so")], 60),
        ("reservation-build", [compiler, *flags, "tests/native_tun_reservation_test.cpp", "-o", str(output / "reservation")], 120),
        ("reservation-helper", [str(output / "reservation")], 60),
    ]
    try:
        for name, command, timeout in commands:
            started = time.monotonic()
            record = {"name": name, "command": command, "timeoutSeconds": timeout}
            try:
                with (output / f"{name}.stdout.log").open("wb") as stdout, (output / f"{name}.stderr.log").open("wb") as stderr:
                    proc = subprocess.run(command, cwd=root, env=env, stdout=stdout, stderr=stderr, timeout=timeout, check=False)
                record.update(status="Pass" if proc.returncode == 0 else "Fail", exitCode=proc.returncode)
            except (OSError, subprocess.TimeoutExpired) as exc:
                record.update(status="Fail", error=str(exc))
            record["elapsedSeconds"] = round(time.monotonic() - started, 3)
            results.append(record)
            (output / "steps.partial.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
            if record["status"] != "Pass":
                break
    finally:
        after = inputs()
        (output / "inputs-after.json").write_text(json.dumps(after, indent=2), encoding="utf-8")
        passed = len(results) == len(commands) and all(r["status"] == "Pass" for r in results) and before == after
        manifest = {"schemaVersion": 1, "status": "Pass" if passed else "Fail", "fixedTestInputBytes": before == after,
                    "system": platform.platform(), "results": results, "formalReleaseAllowed": False,
                    "scope": "Production TCP parser offline; C++ SO model; exact driver reservation helper with host shims",
                    "notExecuted": ["C# compilation/tests", "WinForms/UAC", "WinDivert/Wintun native I/O", "research SYS or CSQ/IRQL", "real NAT/WAN", "installed package/quality"],
                    "binaries": {str(p.relative_to(output)): hashlib.sha256(p.read_bytes()).hexdigest()
                                 for p in (output / "so", output / "reservation", output / "parser/native-parser-asan") if p.is_file()}}
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({"status": manifest["status"], "manifest": str(output / "manifest.json"), "formalReleaseAllowed": False}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
