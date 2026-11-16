"""Create local experimental archives. Does not install, publish, or download.

Build conwu with DEFAULT features first. Cargo is used only for offline
dependency metadata; all native binaries and official DLLs must already exist.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parent.parent
PRODUCT = "{2B716DCB-5CD7-4EEC-91E4-749BC09027A1}"
VERSION = tomllib.loads((ROOT / "rust/Cargo.toml").read_text(encoding="utf-8"))["workspace"]["package"]["version"]
OUTPUT = ROOT / "out/rust-experiment"


def read(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Missing or linked input: {path}")
    return path.read_bytes()


def encode(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def zipped(files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for name, (data, mode) in sorted(files.items()):
            info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (0o100000 | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    return buffer.getvalue()


def save(name, data):
    # Only replace an explicitly named regular archive beneath our own output.
    target = OUTPUT / name
    assert target.parent.resolve() == OUTPUT.resolve() and target.name == name
    for path in (target, target.with_name(name + ".part")):
        if path.is_symlink() or path.exists() and not path.is_file():
            raise ValueError(f"Refusing to replace non-file: {path}")
    temporary = target.with_name(name + ".part")
    temporary.write_bytes(data)
    os.replace(temporary, target)
    return target


def sources():
    files = {}
    selected = ["rust", "transport", "third-party", "tests", "scripts",
                "src/ConWU.Web/wwwroot", "src/ConWU.Core", "src/ConWU.App/Assets/conwu.ico",
                ".cargo/config.toml", "CMakeLists.txt", "LICENSE", "README.md", "docs"]
    excluded = {"target", "bin", "obj", "out", ".git", "__pycache__"}
    for relative in selected:
        path = ROOT / relative
        candidates = [path] if path.is_file() else sorted(path.rglob("*"))
        for item in candidates:
            rel = item.relative_to(ROOT)
            if not item.is_file() or excluded.intersection(rel.parts):
                continue
            if item.suffix in {".pem", ".key", ".pfx", ".dpapi", ".log"} or item.name.endswith(".private.json"):
                continue
            files[rel.as_posix()] = (read(item), 0o755 if item.suffix == ".sh" else 0o644)
    return files


def dependencies(platform):
    target = "x86_64-pc-windows-msvc" if platform == "windows" else "x86_64-unknown-linux-gnu"
    packages = {}
    for manifest in ("rust/Cargo.toml", "transport/phantun/Cargo.toml"):
        result = subprocess.run(["cargo", "metadata", "--locked", "--offline", "--format-version", "1",
                                 "--filter-platform", target, "--manifest-path", manifest],
                                cwd=ROOT, check=True, capture_output=True, text=True, encoding="utf-8")
        metadata = json.loads(result.stdout)
        for package in metadata["packages"]:
            if package["source"]:
                packages[(package["name"], package["version"])] = package
    notices = {}
    index = []
    for (name, version), package in sorted(packages.items()):
        index.append({key: package.get(key) for key in ("name", "version", "license", "repository", "source")})
        directory = Path(package["manifest_path"]).parent
        for item in directory.iterdir():
            if item.is_file() and item.name.upper().startswith(("LICENSE", "COPYING", "NOTICE", "AUTHORS")):
                notices[f"licenses/cargo/{name}-{version}/{item.name}"] = (read(item), 0o644)
        license_file = package.get("license_file")
        if license_file:
            item = directory / license_file
            if item.is_file():
                notices[f"licenses/cargo/{name}-{version}/{item.name}"] = (read(item), 0o644)
    notices["licenses/cargo/dependencies.json"] = (encode(index), 0o644)
    return notices


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=["windows", "linux"], required=True)
    parser.add_argument("--dependency-root", type=Path, default=ROOT / "out/dependency-cache")
    parser.add_argument("--app", type=Path)
    args = parser.parse_args()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    if OUTPUT.is_symlink() or OUTPUT.resolve().parent != (ROOT / "out").resolve():
        raise ValueError("Output directory must remain within this worktree's out directory")

    source_files = sources()
    source_digest = hashlib.sha256(encode({name: hashlib.sha256(data).hexdigest()
                                         for name, (data, _) in sorted(source_files.items())})).hexdigest()
    source_name = f"conwu-rust-{VERSION}-source.zip"
    source_zip = zipped(source_files)
    save(source_name, source_zip)
    files = {"source/" + source_name: (source_zip, 0o644)}
    files.update(dependencies(args.platform))
    executable = "conwu.exe" if args.platform == "windows" else "conwu"
    target_dir = ROOT / ("out/rust-target" if args.platform == "windows" else "out/rust-target-linux")
    files[executable] = (read(args.app or target_dir / "release" / executable), 0o755)
    native_dir = ROOT / ("out/native" if args.platform == "windows" else "out/rust-components-linux")
    for name in ("conwu-raw", "conwu-phantun", "udp2raw-native"):
        basename = name + (".exe" if args.platform == "windows" else "")
        directory = target_dir / "release" if args.platform == "windows" and name != "udp2raw-native" else native_dir
        files["components/" + basename] = (read(directory / basename), 0o755)
    if args.platform == "windows":
        dlls = {
            "wintun.dll": "wintun/bin/amd64/wintun.dll",
            "WinDivert.dll": "WinDivert-2.2.2-A/x64/WinDivert.dll",
            "WinDivert64.sys": "WinDivert-2.2.2-A/x64/WinDivert64.sys",
            "xdpapi.dll": "xdp-1.4.0/unpacked/runtime/native/xdpapi.dll",
        }
        for name, source in dlls.items():
            files["components/" + name] = (read(args.dependency_root / source), 0o644)
    licenses = {
        "LICENSE": "LICENSE",
        "udp2raw-LICENSE.md": "transport/udp2raw/LICENSE.md",
        "libev-LICENSE": "transport/udp2raw/libev/LICENSE",
        "Phantun-LICENSE-MIT": "transport/phantun/LICENSE-MIT",
        "Phantun-LICENSE-APACHE": "transport/phantun/LICENSE-APACHE",
        "Mimic-GPL-2.0": "transport/phantun/conwu-raw/LICENSE",
        "TCPRAW-LICENSE": "transport/phantun/conwu-raw/TCPRAW-LICENSE",
        "XDP-SDK-LICENSE": "transport/phantun/conwu-raw/native/xdp-sdk/LICENSE",
        "Wintun-LICENSE": "third-party/wintun/LICENSE.txt",
        "WinDivert-LICENSE": "third-party/windivert/LICENSE",
    }
    for name, source in licenses.items():
        files["licenses/" + name] = (read(ROOT / source), 0o644)
    for item in (ROOT / "docs/licenses").iterdir():
        if item.is_file(): files["licenses/native/" + item.name] = (read(item), 0o644)
    files["README.md"] = (read(ROOT / "rust/README.md"), 0o644)
    for name in ("ARCHITECTURE.md", "VALIDATION.md"):
        files["docs/" + name] = (read(ROOT / "rust" / name), 0o644)
    for name in ("app-test.log", "linux-test.log", "interop.log", "migration-test.log", "ui-smoke.log", "rust-ui-smoke.png",
                 "native-lab-result.json", "native-lab.log", "tun-lab-result.json", "tun-lab.log",
                 "benchmark-baseline.json", "benchmark-result.json", "carriers-build.log",
                 "linux-build-info.txt", "windows-build-info.txt"):
        item = ROOT / "out" / name
        if item.is_file(): files["evidence/" + name] = (read(item), 0o644)
    files[".conwu-rust-package"] = (encode({"product": PRODUCT, "version": VERSION,
        "os": args.platform, "arch": "x86_64", "experimental": True, "features": [],
        "sourceTreeSha256": source_digest, "sourceArchive": source_name,
        "deploymentValidated": False, "published": False}), 0o644)
    files["SHA256SUMS"] = ("".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n"
                                  for name, (data, _) in sorted(files.items())).encode(), 0o644)
    name = f"conwu-rust-{VERSION}-{args.platform}-x86_64"
    if args.platform == "windows":
        artifact = save(name + ".zip", zipped(files))
    else:
        buffer = io.BytesIO()
        with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                for relative, (data, mode) in sorted(files.items()):
                    item = tarfile.TarInfo(relative)
                    item.size = len(data)
                    item.mode = mode
                    archive.addfile(item, io.BytesIO(data))
        artifact = save(name + ".tar.gz", buffer.getvalue())
    sums = []
    for item in sorted(OUTPUT.iterdir()):
        if item.name.endswith((".zip", ".tar.gz")) and item.is_file():
            sums.append(f"{hashlib.sha256(read(item)).hexdigest()}  {item.name}\n")
    save("SHA256SUMS", "".join(sums).encode())
    print(json.dumps({"artifact": str(artifact), "bytes": artifact.stat().st_size,
                      "sourceTreeSha256": source_digest, "installed": False, "published": False}))


if __name__ == "__main__":
    main()
