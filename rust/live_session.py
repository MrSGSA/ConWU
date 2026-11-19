"""Read-only preflight for disruptive Windows carrier/adapter experiments."""
import ctypes as c
import hashlib
import json
import os
from pathlib import Path
import queue
import sys
import threading


def production_status():
    if os.name != 'nt':
        return None
    kernel=c.WinDLL('kernel32',use_last_error=True)
    advapi=c.WinDLL('advapi32',use_last_error=True)
    advapi.OpenSCManagerW.argtypes=[c.c_wchar_p,c.c_wchar_p,c.c_uint32]
    advapi.OpenSCManagerW.restype=c.c_void_p
    advapi.OpenServiceW.argtypes=[c.c_void_p,c.c_wchar_p,c.c_uint32]
    advapi.OpenServiceW.restype=c.c_void_p
    advapi.CloseServiceHandle.argtypes=[c.c_void_p]
    advapi.QueryServiceStatusEx.argtypes=[c.c_void_p,c.c_int,c.c_void_p,c.c_uint32,c.POINTER(c.c_uint32)]
    manager=advapi.OpenSCManagerW(None,None,1)
    if not manager: raise c.WinError(c.get_last_error())
    service=None
    try:
        service=advapi.OpenServiceW(manager,'StreamLink-PersonalFeature',4)
        if not service:
            if c.get_last_error()==1060:return None
            raise c.WinError(c.get_last_error())
        status=(c.c_uint32*9)();size=c.c_uint32()
        if not advapi.QueryServiceStatusEx(service,0,status,c.sizeof(status),c.byref(size)):
            raise c.WinError(c.get_last_error())
        if status[1]!=4:return None
        service_pid=status[7]
    finally:
        if service:advapi.CloseServiceHandle(service)
        advapi.CloseServiceHandle(manager)
    data=str(Path(os.environ.get('ProgramData',r'C:\ProgramData'))/'ConWU').lower()
    name=r'\\.\pipe\ConWU.Rust.Control.'+hashlib.sha256(data.encode()).hexdigest()[:24]
    kernel.CreateFileW.argtypes=[c.c_wchar_p,c.c_uint32,c.c_uint32,c.c_void_p,c.c_uint32,c.c_uint32,c.c_void_p]
    kernel.CreateFileW.restype=c.c_void_p
    kernel.GetNamedPipeServerProcessId.argtypes=[c.c_void_p,c.POINTER(c.c_uint32)]
    kernel.ReadFile.argtypes=[c.c_void_p,c.c_void_p,c.c_uint32,c.POINTER(c.c_uint32),c.c_void_p]
    kernel.WriteFile.argtypes=kernel.ReadFile.argtypes
    kernel.CloseHandle.argtypes=[c.c_void_p]
    handle=kernel.CreateFileW(name,0xC0000000,0,None,3,0,None)
    if handle==c.c_void_p(-1).value:raise c.WinError(c.get_last_error())
    try:
        server_pid=c.c_uint32()
        if not kernel.GetNamedPipeServerProcessId(handle,c.byref(server_pid)) or server_pid.value!=service_pid:
            raise RuntimeError('生产控制管道与 SCM 进程不符')
        def read_exact(length):
            output=bytearray()
            while len(output)<length:
                buf=c.create_string_buffer(length-len(output));done=c.c_uint32()
                if not kernel.ReadFile(handle,buf,len(buf),c.byref(done),None) or not done.value:
                    raise RuntimeError('生产状态读取失败')
                output.extend(buf.raw[:done.value])
            return bytes(output)
        request=b'{"method":"status"}'
        frame=len(request).to_bytes(4,'little')+request;done=c.c_uint32()
        if not kernel.WriteFile(handle,frame,len(frame),c.byref(done),None) or done.value!=len(frame):
            raise RuntimeError('生产状态请求失败')
        size=int.from_bytes(read_exact(4),'little')
        if size>8*1024*1024:raise RuntimeError('生产状态超过大小限制')
        return json.loads(read_exact(size))['status']
    finally:
        kernel.CloseHandle(handle)


def require_idle():
    if os.name!='nt':return
    result=queue.Queue(maxsize=1)
    def check():
        try:result.put((production_status(),None))
        except Exception as error:result.put((None,str(error)))
    worker=threading.Thread(target=check,daemon=True);worker.start();worker.join(4)
    if worker.is_alive():raise SystemExit('未能及时确认日用会话状态，未启动网卡/承载实验。')
    status,error=result.get_nowait()
    if error:raise SystemExit('未启动网卡/承载实验，日用状态未确认：'+error)
    if not status:return
    uu=status.get('uuTakeover') or {}
    observed=uu.get('trafficObserved') or any(n.get('trafficObserved') for n in uu.get('networks',[]))
    connected=any(n.get('status',{}).get('directPeers',0)>0 for n in status.get('networks',[]))
    if connected and uu.get('settings',{}).get('enabled') and uu.get('rulesActive'):
        if uu.get('observationAvailable') is False:
            raise SystemExit('日用 UU 规则仍在工作，暂时无法确认流量，未启动网卡重建/承载实验。')
        if observed:
            raise SystemExit('检测到日用 UU 正在经 ConWU 传输，未启动网卡重建/承载实验。请在会话空闲时运行。')


if __name__=='__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
    require_idle()
    print('未检测到正在传输的日用 UU 会话。')
