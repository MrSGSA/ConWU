"""Collect notices and actual resolved Cargo identities for the native bundle."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import tomllib

parser=argparse.ArgumentParser()
parser.add_argument("--directory",type=Path,required=True)
parser.add_argument("--cargo",default="cargo")
parser.add_argument("--target",default="x86_64-pc-windows-msvc")
args=parser.parse_args()
repo=Path(__file__).resolve().parent.parent
source=repo/"transport/phantun"
result=subprocess.run([args.cargo,"metadata","--format-version","1","--locked","--offline","--filter-platform",args.target],cwd=source,capture_output=True,text=True,encoding="utf-8",errors="replace",check=True)
metadata=json.loads(result.stdout)
nodes={node["id"]:node for node in metadata["resolve"]["nodes"]}
reachable=set();pending=list(metadata["workspace_members"])
while pending:
 identity=pending.pop()
 if identity in reachable:continue
 reachable.add(identity)
 pending.extend(edge["pkg"] for edge in nodes[identity]["deps"])
lock=tomllib.loads((source/"Cargo.lock").read_text(encoding="utf-8"))
checksums={(entry["name"],entry["version"]):entry.get("checksum","") for entry in lock["package"]}
destination=args.directory.resolve()/"licenses/phantun"
destination.mkdir(parents=True,exist_ok=True)
for name in ["LICENSE-MIT","LICENSE-APACHE","README.md"]:shutil.copy2(source/name,destination/name)
raw_notices=args.directory.resolve()/"licenses/raw-carriers"
raw_notices.mkdir(parents=True,exist_ok=True)
for name in ["LICENSE","TCPRAW-LICENSE","README.md"]:shutil.copy2(source/"conwu-raw"/name,raw_notices/name)
packages=[]
for package in sorted(metadata["packages"],key=lambda p:(p["name"],p["version"])):
 if package["id"] not in reachable:continue
 name,version=package["name"],package["version"]
 if not re.fullmatch(r"[a-zA-Z0-9_-]+",name) or not re.fullmatch(r"[a-zA-Z0-9.+_-]+",version):raise ValueError("unexpected Cargo package identity")
 entry={"name":name,"version":version,"license":package.get("license") or "NOASSERTION","repository":package.get("repository") or "NOASSERTION","purl":f"pkg:cargo/{name}@{version}","registryChecksum":checksums.get((name,version),"")}
 packages.append(entry)
 package_root=Path(package["manifest_path"]).parent
 candidates=[*package_root.glob("*"),*(package_root/"licenses").glob("*"),*(package_root/"license").glob("*")]
 if name=="windivert-sys":candidates.extend((package_root/"vendor").glob("LICENSE*"))
 for notice in candidates:
  if notice.is_file() and re.match(r"^(LICEN[CS]E|COPYING|NOTICE|THIRD.PARTY)",notice.name,re.I):
   target=destination/(name+"-"+version);target.mkdir(exist_ok=True);shutil.copy2(notice,target/notice.name)
rustc=Path(shutil.which(args.cargo) or args.cargo).with_name("rustc.exe" if __import__('os').name=='nt' else "rustc")
sysroot=Path(subprocess.run([str(rustc),"--print","sysroot"],capture_output=True,text=True,check=True).stdout.strip())
for base in [sysroot/"share/doc/rust",sysroot/"lib/rustlib"]:
 for notice in base.glob("*"):
  if notice.is_file() and re.match(r"^(LICENSE|COPYRIGHT-library|THIRD.PARTY)",notice.name,re.I):
   target=destination/"rust-runtime";target.mkdir(exist_ok=True);shutil.copy2(notice,target/notice.name)
(destination/"dependencies.json").write_text(json.dumps({"component":"ConWU.PacketCarriers","components":["ConWU.Phantun","ConWU.RawCarriers"],"wire":"Phantun 0.8; Mimic zero-padding; TCPRAW kernel handshake","target":args.target,"packages":packages},ensure_ascii=False,indent=2),encoding="utf-8")
print(json.dumps({"noticePackages":len(packages),"destination":str(destination)}))
