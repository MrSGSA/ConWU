"""Create versioned runtime/source archives. Does not install, publish, or download.

Build conwu with the matching production/local-install features first. Cargo is used only for offline
dependency metadata; all native binaries and official DLLs must already exist.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import tomllib
import zipfile
import uuid

ROOT = Path(__file__).resolve().parent.parent
PRODUCT = "{2B716DCB-5CD7-4EEC-91E4-749BC09027A1}"
VERSION = tomllib.loads((ROOT / "rust/Cargo.toml").read_text(encoding="utf-8"))["workspace"]["package"]["version"]
OUTPUT = ROOT / "out/rust-experiment"
SOURCE_INPUTS = ["rust", "transport", "third-party", "tests", "scripts", "src", "installer", "packaging",
                 ".cargo/config.toml", "CMakeLists.txt", "LICENSE", "README.md", "docs",
                 "Directory.Build.props", "Directory.Build.targets", "global.json", "NuGet.Config",
                 "ConWU.sln", "ConWU.slnx", "StreamLink.sln"]
PROJECTION_ASSETS = {
    "sunshine": (
        "Sunshine-Windows-AMD64-lite.zip",
        "233008e46f4c0e501a586cbfd6c4fd4a4c0d414a0b5fc7f13c070eb92ec3824b",
        "Sunshine/",
        "sunshine.exe",
    ),
    "moonlight": (
        "MoonlightPortable-x64-6.2.0.zip",
        "6f91d268b41ed5ca8066d9d7578dc403b8db190991ff48f00b1700465f8f7ebf",
        "",
        "Moonlight.exe",
    ),
}


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
    # Honour the repository's input list; never traverse ignored build caches.
    result = subprocess.run(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard', '--', *SOURCE_INPUTS],
                            cwd=ROOT, capture_output=True, check=True)
    for name in sorted(set(result.stdout.decode('utf-8').split('\0')) - {''}):
        item = ROOT / name
        if not item.is_file():
            continue
        if item.suffix in {".pem", ".key", ".pfx", ".dpapi", ".log"} or item.name.endswith(".private.json"):
            continue
        files[name] = (read(item), 0o755 if item.suffix == ".sh" else 0o644)
    return files


def dependencies(platform, linux_target, include_desktop, projection, projection_cargo_home):
    target = "x86_64-pc-windows-msvc" if platform == "windows" else linux_target
    packages = {}
    manifests = [(ROOT / path, None) for path in ("rust/Cargo.toml", "transport/phantun/Cargo.toml")]
    if include_desktop:
        manifests.append((ROOT / "rust/desktop/Cargo.toml", None))
    if projection:
        manifests.append((projection / "Cargo.toml", dict(os.environ, CARGO_HOME=str(projection_cargo_home))))
    for manifest, env in manifests:
        result = subprocess.run(["cargo", "metadata", "--locked", "--offline", "--format-version", "1",
                                 "--filter-platform", target, "--manifest-path", manifest],
                                cwd=ROOT, env=env, check=True, capture_output=True, text=True, encoding="utf-8")
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


def projection_source(directory):
    files = {}
    for name in ("Cargo.toml", "Cargo.lock", "README.md", "build.ps1", ".cargo/config.toml"):
        files[name] = (read(directory / name), 0o644)
    for folder in ("src", "assets"):
        for path in (directory / folder).rglob("*"):
            if path.is_file():
                files[path.relative_to(directory).as_posix()] = (read(path), 0o644)
    return zipped(files)


def projection_runtime(directory, embedded):
    def linked(path):
        return path.is_symlink() or (
            os.name == "nt" and path.exists() and path.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
        )

    files = {}
    for engine, (filename, digest, prefix, executable) in PROJECTION_ASSETS.items():
        data = read(directory / filename)
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError(f"Projection upstream asset SHA-256 mismatch: {filename}")
        component = f"app/components/projection/{engine}/"
        if engine == "moonlight":
            if linked(embedded) or not embedded.is_dir():
                raise ValueError("Embedded Moonlight runtime must be a regular directory")
            for path in sorted(embedded.rglob("*")):
                if linked(path):
                    raise ValueError(f"Linked embedded runtime input: {path}")
                if path.is_file():
                    relative = path.relative_to(embedded).as_posix()
                    if path.name == "portable.dat":
                        continue
                    if path.name.casefold() == executable.casefold():
                        raise ValueError("Use the staged ConWU-Moonlight runtime")
                    files[component + relative] = (read(path), 0o755 if path.name.endswith(".exe") else 0o644)
            for required in ("ConWU-Moonlight.exe", "platforms/qwindows.dll", "SDL2.dll", "SDL3.dll", "AntiHooking.dll"):
                if component + required not in files:
                    raise ValueError(f"Embedded Moonlight runtime missing {required}")
            if b"CONWU_PROJECTION_CARRIER" not in files[component + "ConWU-Moonlight.exe"][0]:
                raise ValueError("Rebuild embedded Moonlight with the current Projection statistics patch")
            # Reuse the compiler runtimes the pinned portable Windows release redistributes.
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for entry in archive.infolist():
                    if "/" not in entry.filename and entry.filename.startswith(("msvcp140", "vcruntime140")) and entry.filename.endswith(".dll"):
                        files.setdefault(component + entry.filename, (archive.read(entry), 0o644))
            continue
        paths = set()
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for entry in archive.infolist():
                if entry.is_dir():
                    continue
                relative = entry.filename.removeprefix(prefix)
                if (not entry.filename.startswith(prefix) or "\\" in relative or ":" in relative
                        or any(part in {"", ".", ".."} for part in relative.split("/"))
                        or stat.S_ISLNK(entry.external_attr >> 16) or relative.casefold() in paths):
                    raise ValueError(f"Invalid path in {filename}: {entry.filename}")
                paths.add(relative.casefold())
                if engine == "sunshine" and relative.startswith(("scripts/", "tools/")):
                    continue
                mode = 0o755 if relative == executable else 0o644
                files[component + relative] = (archive.read(entry), mode)
        if component + executable not in files:
            raise ValueError(f"Projection executable missing from {filename}")
    # Upstream expects a config directory beside sunshine.exe. All writable
    # configuration paths used by Projection point to the user's own directory.
    files["app/components/projection/sunshine/config/README.txt"] = (
        b"Projection runtime. Per-user configuration is stored in LocalAppData.\n", 0o644
    )
    licenses = ROOT / "third-party/projection"
    for name in ("Sunshine-GPL-3.0.txt", "Sunshine-NOTICE.txt", "Moonlight-GPL-3.0.txt", "SDL3-LICENSE.txt"):
        files[f"licenses/{name}"] = (read(licenses / name), 0o644)
    files["source/Projection-upstream.md"] = (read(licenses / "README.md"), 0o644)
    files["source/Projection-Moonlight.patch"] = (read(licenses / "moonlight-conwu.patch"), 0o644)
    files["source/Projection-SDL3.patch"] = (read(licenses / "sdl3-conwu.patch"), 0o644)
    return files


def main():
    global OUTPUT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=["windows", "linux"], required=True)
    parser.add_argument("--dependency-root", type=Path, default=ROOT / "out/dependency-cache")
    parser.add_argument("--app", type=Path)
    parser.add_argument("--desktop", type=Path, help="Include the built Windows Tauri desktop shell")
    parser.add_argument("--component-root", type=Path)
    parser.add_argument("--target-directory", type=Path)
    parser.add_argument("--linux-target", default="x86_64-unknown-linux-musl")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--stage", action="store_true", help="Also write the exact MSI/runtime input directory")
    parser.add_argument("--production", action="store_true")
    parser.add_argument("--validation-instance")
    parser.add_argument("--projection-app", type=Path)
    parser.add_argument("--projection-source", type=Path)
    parser.add_argument("--projection-cargo-home", type=Path)
    parser.add_argument("--projection-runtime", type=Path,
                        help="Read the pinned Sunshine and Moonlight Windows release ZIPs from this directory")
    parser.add_argument("--projection-embedded-runtime", type=Path,
                        help="Use the staged ConWU-Moonlight build and its matching DLLs")
    args = parser.parse_args()
    if args.desktop and args.platform != "windows":
        parser.error("--desktop requires --platform windows")
    projection_inputs = (args.projection_app, args.projection_source, args.projection_cargo_home)
    if args.projection_runtime and (args.platform != "windows" or any(projection_inputs)):
        parser.error("--projection-runtime is for Windows and replaces the legacy Projection build inputs")
    if args.projection_runtime and not (args.projection_embedded_runtime and args.desktop):
        parser.error("--projection-runtime requires --projection-embedded-runtime and --desktop")
    if args.projection_embedded_runtime and not (args.projection_runtime and args.desktop):
        parser.error("--projection-embedded-runtime requires --projection-runtime and --desktop")
    if any(projection_inputs) and (args.platform != "windows" or not all(projection_inputs)):
        parser.error("Projection requires all three component inputs and a Windows bundle")
    OUTPUT = args.output.resolve()
    if not OUTPUT.is_relative_to((ROOT / 'out').resolve()) or OUTPUT == (ROOT / 'out').resolve():
        raise ValueError('Package output must be a dedicated directory beneath this worktree/out')
    product = "{AD076018-A9B8-47F5-B098-97479A363416}" if args.production else PRODUCT
    if args.validation_instance:
        identity = uuid.UUID(hex=args.validation_instance)
        if identity.int == 0 or identity.hex != args.validation_instance:
            raise ValueError('Canonical validation GUID required')
        product = '{' + str(identity).upper() + '}'
    if args.production:
        changes = subprocess.run(['git', 'status', '--porcelain', '--untracked-files=normal', '--', *SOURCE_INPUTS],
                                 cwd=ROOT, capture_output=True, check=True)
        if changes.stdout.strip():
            raise ValueError('Production packaging requires committed, unchanged source and build inputs')
    OUTPUT.mkdir(parents=True, exist_ok=True)
    if OUTPUT.is_symlink():
        raise ValueError("Output directory must remain within this worktree's out directory")

    source_files = sources()
    source_digest = hashlib.sha256(encode({name: hashlib.sha256(data).hexdigest()
                                         for name, (data, _) in sorted(source_files.items())})).hexdigest()
    prefix = f"ConWU-{VERSION}" if args.production else f"conwu-rust-{VERSION}"
    source_name = prefix + "-source.zip"
    source_zip = zipped(source_files)
    save(source_name, source_zip)
    files = {"source/" + source_name: (source_zip, 0o644)}
    files.update(dependencies(args.platform, args.linux_target, args.desktop is not None,
                              args.projection_source, args.projection_cargo_home))
    executable = "conwu.exe" if args.platform == "windows" else "conwu"
    target_dir = args.target_directory or ROOT / ("out/rust-target" if args.platform == "windows" else "out/rust-target-linux")
    app = (args.app or target_dir / "release" / executable).resolve()
    command = [str(app)]
    if args.platform == 'linux' and os.name == 'nt':
        command = ['wsl', '-d', 'ArchLinux', '-u', 'root', '--', '/mnt/' + app.drive[0].lower() + app.as_posix()[2:]]
    if args.validation_instance:
        command += ['--validation-instance', args.validation_instance]
    info = json.loads(subprocess.check_output(command + ['build-info'], text=True, encoding='utf-8'))
    if info['version'] != VERSION or info['product'] != product or info['labApi'] or info['production'] != args.production:
        raise ValueError('Executable build identity/features do not match this package')
    if args.production and not info['localInstall']:
        raise ValueError('Production candidate must support local installation')
    app_bytes = read(app)
    component_prefix = 'app/components/' if args.platform == 'windows' else 'components/'
    if args.platform == 'windows':
        for name in ('ConWU.exe', 'app/ConWU.exe', 'app/ConWU.Service.exe'):
            files[name] = (app_bytes, 0o755)
        if args.desktop:
            files[component_prefix + 'ConWU-Desktop.exe'] = (read(args.desktop), 0o755)
        if args.projection_runtime:
            files.update(projection_runtime(args.projection_runtime, args.projection_embedded_runtime))
        if args.projection_app:
            version = tomllib.loads(read(args.projection_source / "Cargo.toml").decode())["package"]["version"]
            files[component_prefix + 'ConWU-Projection.exe'] = (read(args.projection_app), 0o755)
            files[f"source/ConWU-Projection-{version}-source.zip"] = (projection_source(args.projection_source), 0o644)
    else:
        files[executable] = (app_bytes, 0o755)
        files['install.sh'] = (read(ROOT / 'rust/install-linux.sh'), 0o755)
        files['install.py'] = (read(ROOT / 'rust/install-linux.py'), 0o644)
        files['uninstall.sh'] = (read(ROOT / 'rust/uninstall-linux.sh'), 0o755)
    native_dir = args.component_root or ROOT / ("out/native" if args.platform == "windows" else "out/rust-components-linux-musl")
    for name in ("conwu-raw", "conwu-phantun", "udp2raw-native"):
        basename = name + (".exe" if args.platform == "windows" else "")
        directory = target_dir / "release" if args.platform == "windows" and name != "udp2raw-native" else native_dir
        files[component_prefix + basename] = (read(directory / basename), 0o755)
    if args.platform == 'linux':
        subprocess.run(['python', str(ROOT / 'rust/verify-linux-static.py'), str(app)] +
            [str(native_dir / name) for name in ('conwu-raw', 'conwu-phantun', 'udp2raw-native')], check=True)
    if args.platform == "windows":
        dlls = {
            "wintun.dll": "wintun/bin/amd64/wintun.dll",
            "WinDivert.dll": "WinDivert-2.2.2-A/x64/WinDivert.dll",
            "WinDivert64.sys": "WinDivert-2.2.2-A/x64/WinDivert64.sys",
            "xdpapi.dll": "xdp-1.4.0/unpacked/runtime/native/xdpapi.dll",
        }
        for name, source in dlls.items():
            files[component_prefix + name] = (read(args.dependency_root / source), 0o644)
        runtime = args.dependency_root / 'xdp-1.4.0/unpacked/runtime/native'
        files['licenses/Microsoft-XDP-Runtime-LICENSE.txt'] = (read(runtime / 'LICENSE.txt'), 0o644)
        metadata = json.loads(read(runtime / 'xdp-runtime.json'))
        for name, digest in metadata['files'].items():
            if hashlib.sha256(read(runtime / name)).hexdigest().upper() != digest:
                raise ValueError('Microsoft XDP runtime hash mismatch: ' + name)
        for name in ('xdp.inf', 'xdp.sys', 'xdp.cat', 'xdpapi.dll', 'xdp-setup.ps1', 'xdppcw.man', 'xdp-runtime.json'):
            files[component_prefix + 'xdp-runtime/' + name] = (read(runtime / name), 0o644)
        files[component_prefix + 'install-xdp.ps1'] = (b'\xef\xbb\xbf' + read(ROOT / 'rust/install-xdp.ps1'), 0o644)
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
    for name in (() if args.production else ("app-test.log", "linux-test.log", "interop.log", "migration-test.log", "ui-smoke.log", "rust-ui-smoke.png",
                 "native-lab-result.json", "native-lab.log", "tun-lab-result.json", "tun-lab.log",
                 "benchmark-baseline.json", "benchmark-result.json", "carriers-build.log",
                 "linux-build-info.txt", "windows-build-info.txt")):
        item = ROOT / "out" / name
        if item.is_file(): files["evidence/" + name] = (read(item), 0o644)
    files[".conwu-rust-package"] = (encode({"product": product, "version": VERSION,
        "os": args.platform, "arch": "x86_64", "experimental": not args.production,
        "features": [name for name, enabled in [('production', info['production']), ('local-install', info['localInstall'])] if enabled],
        "sourceTreeSha256": source_digest, "sourceArchive": source_name,
        "validationInstance": args.validation_instance}), 0o644)
    files["SHA256SUMS"] = ("".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n"
                                  for name, (data, _) in sorted(files.items())).encode(), 0o644)
    if args.stage:
        stage = OUTPUT / (args.platform + '-bundle')
        if stage.is_symlink(): raise ValueError('Stage directory cannot be linked')
        if stage.is_dir() and any(stage.iterdir()):
            raise ValueError('Stage must be a fresh empty directory; keep a new candidate separate from an accepted bundle')
        stage.mkdir(exist_ok=True)
        for relative, (data, _) in sorted(files.items()):
            target = stage / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.is_symlink(): raise ValueError('Stage file cannot be linked')
            target.write_bytes(data)
    name = prefix + (f"-{args.platform}-x64" if args.production else f"-{args.platform}-x86_64")
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
