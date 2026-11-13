"""Verify a bare native carrier exits after its only owning parent is killed.

No test payload, router mapping, application profile or firewall rule is used.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

parser=argparse.ArgumentParser();parser.add_argument("--component",type=Path,required=True);parser.add_argument("--child",action="store_true");parser.add_argument("--output",type=Path)
parser.add_argument("--carrier",choices=["phantun","mimic","tcpraw"],default="phantun")
args=parser.parse_args()
if args.child:
    lease=socket.socket()
    if os.name=="nt":lease.setsockopt(socket.SOL_SOCKET,socket.SO_EXCLUSIVEADDRUSE,1)
    lease.bind(("0.0.0.0",0))
    port=lease.getsockname()[1]
    if args.carrier=="tcpraw":lease.close()
    options=[] if args.carrier=="phantun" else ["--carrier",args.carrier]
    component=subprocess.Popen([str(args.component),"--server","--source","0.0.0.0:"+str(port),"--remote","127.0.0.1:49199","--parent",str(os.getpid()),*options],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
    line=component.stdout.readline()
    prefix="CONWU_PHANTUN " if args.carrier=="phantun" else "CONWU_RAW "
    if not line.startswith(prefix):raise RuntimeError("fixture component not ready")
    ready=json.loads(line[len(prefix):])
    if ready.get("event")!="ready":raise RuntimeError("fixture native initialization failed")
    print(json.dumps({"pid":component.pid,"port":port}),flush=True)
    sys.stdin.buffer.read(1)
    component.stdin.write("stop\n");component.stdin.flush();component.wait(timeout=5)
    raise SystemExit()

owner=subprocess.Popen([sys.executable,str(Path(__file__).resolve()),"--child","--component",str(args.component.resolve()),"--carrier",args.carrier],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
native=None;handle=None
try:
    import queue,threading
    ready=queue.Queue()
    threading.Thread(target=lambda:ready.put(owner.stdout.readline()),daemon=True).start()
    native=json.loads(ready.get(timeout=15))
    if os.name=="nt":
        kernel=ctypes.WinDLL("kernel32",use_last_error=True)
        kernel.OpenProcess.restype=ctypes.c_void_p;kernel.OpenProcess.argtypes=[ctypes.c_uint32,ctypes.c_int,ctypes.c_uint32]
        kernel.WaitForSingleObject.argtypes=[ctypes.c_void_p,ctypes.c_uint32];kernel.CloseHandle.argtypes=[ctypes.c_void_p]
        handle=kernel.OpenProcess(0x100000,False,native["pid"])
        if not handle:raise ctypes.WinError(ctypes.get_last_error())
    began=time.monotonic();owner.kill();owner.wait(timeout=5)
    def alive():
        if os.name=="nt":return kernel.WaitForSingleObject(handle,0)==0x102
        try:os.kill(native["pid"],0);return True
        except ProcessLookupError:return False
    while alive() and time.monotonic()-began<5:time.sleep(.025)
    result={"status":"Pass" if not alive() else "Fail","parentPid":owner.pid,"nativePid":native["pid"],"shutdownMs":(time.monotonic()-began)*1000,"parentKilledWithoutDisposal":True,"productionChanged":False}
    if args.output:args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(result,indent=2),encoding="utf-8")
    print(json.dumps(result),flush=True)
    if result["status"]!="Pass":raise RuntimeError("native component outlived its owning parent")
finally:
    if owner.poll() is None:owner.kill();owner.wait(timeout=5)
    if handle:kernel.CloseHandle(handle)
