"""Install verified development components into D: from inside WSL only."""
import hashlib
import subprocess
import tarfile
import sys
from pathlib import Path

cache = Path('/mnt/d/Codex/cache/rust-linux-1.95')
archives = [
    (cache / 'downloads/rustc-1.95.0-x86_64-unknown-linux-gnu.tar.xz', '8426a3d170a5879f5682f5fbdd024a1779b3951e7baba685af2d6dc32a6dfc15'),
    (cache / 'downloads/rust-std-1.95.0-x86_64-unknown-linux-gnu.tar.xz', '047ea7098803d3500fa1072e9cee5392697e21525559e4458128a2bf874aa382'),
]
if '--musl-only' in sys.argv:
    archives=[(cache/'downloads/rust-std-1.95.0-x86_64-unknown-linux-musl.tar.xz','aee540abf132920f791ef781489851a078d69dff493fb628d49c1d573f92bb3a')]
cargo = cache / 'downloads/cargo-1.95.0-x86_64-unknown-linux-gnu.tar.xz'
if '--musl-only' in sys.argv:
    pass
elif cargo.exists() and cargo.stat().st_size:
    archives.append((cargo, 'e74edd2cf7d0f1f1383b4f00eb90c843750bc489e2ccf7214e6476678a907425'))
else:
    # The newer official Cargo download is independently SHA-256 verified by
    # rustup. Cargo is a build frontend; the compiler and std remain 1.95.0.
    archives.append((Path('/mnt/d/Codex/cache/rustup-linux-rust-rewrite/downloads/7e29ce07d7c6e92d1826870575ba27d57fff6cb3e754aa57d99099cb88fab35d'), '7e29ce07d7c6e92d1826870575ba27d57fff6cb3e754aa57d99099cb88fab35d'))
extract = cache / 'extracted'
extract.mkdir(exist_ok=True)
prefix = cache / 'toolchain'
for archive, expected in archives:
    with archive.open('rb') as source:
        assert hashlib.file_digest(source, 'sha256').hexdigest() == expected
    with tarfile.open(archive) as source:
        top = source.getmembers()[0].name.split('/')[0]
        source.extractall(extract, filter='data')
    subprocess.run(['bash', str(extract / top / 'install.sh'), '--prefix=' + str(prefix), '--disable-ldconfig', '--without=rust-docs'], check=True)
subprocess.run([str(prefix / 'bin/rustc'), '--version'], check=True)
subprocess.run([str(prefix / 'bin/cargo'), '--version'], check=True)
