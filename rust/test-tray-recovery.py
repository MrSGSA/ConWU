"""Verify a real isolated tray icon recovers from the shell's recreation event."""
import argparse
import ctypes as c
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--app', type=Path, default=ROOT/'out/rust-target/release/conwu.exe')
args = parser.parse_args()
assert os.name == 'nt'
data = ROOT/'out'/('tray-recovery-'+uuid.uuid4().hex)
process = subprocess.Popen([str(args.app.resolve()), 'run', '--data', str(data), '--memory', '--no-open'],
    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    creationflags=subprocess.CREATE_NO_WINDOW)
user = c.WinDLL('user32', use_last_error=True)
shell = c.WinDLL('shell32', use_last_error=True)
user.FindWindowW.argtypes = [c.c_wchar_p, c.c_wchar_p]
user.FindWindowW.restype = c.c_void_p
user.GetWindowThreadProcessId.argtypes = [c.c_void_p, c.POINTER(c.c_ulong)]
user.PostMessageW.argtypes = [c.c_void_p, c.c_uint, c.c_size_t, c.c_ssize_t]
user.RegisterWindowMessageW.argtypes = [c.c_wchar_p]
user.RegisterWindowMessageW.restype = c.c_uint


class GUID(c.Structure):
    _fields_ = [('a', c.c_ulong), ('b', c.c_ushort), ('cc', c.c_ushort), ('d', c.c_ubyte*8)]


class IDENT(c.Structure):
    _fields_ = [('cbSize', c.c_ulong), ('hWnd', c.c_void_p), ('uID', c.c_uint), ('guidItem', GUID)]


class RECT(c.Structure):
    _fields_ = [('left', c.c_long), ('top', c.c_long), ('right', c.c_long), ('bottom', c.c_long)]


class ICON(c.Structure):
    _fields_ = [('cbSize', c.c_ulong), ('hWnd', c.c_void_p), ('uID', c.c_uint),
        ('uFlags', c.c_uint), ('uCallbackMessage', c.c_uint), ('hIcon', c.c_void_p),
        ('szTip', c.c_wchar*128), ('dwState', c.c_ulong), ('dwStateMask', c.c_ulong),
        ('szInfo', c.c_wchar*256), ('uVersion', c.c_uint), ('szInfoTitle', c.c_wchar*64),
        ('dwInfoFlags', c.c_ulong), ('guidItem', GUID), ('hBalloonIcon', c.c_void_p)]


shell.Shell_NotifyIconGetRect.argtypes = [c.POINTER(IDENT), c.POINTER(RECT)]
shell.Shell_NotifyIconGetRect.restype = c.c_long
shell.Shell_NotifyIconW.argtypes = [c.c_uint, c.POINTER(ICON)]
shell.Shell_NotifyIconW.restype = c.c_int
control = None
try:
    deadline = time.monotonic()+30
    window = None
    while time.monotonic() < deadline:
        assert process.poll() is None, 'Isolated tray process exited'
        found = user.FindWindowW('ConWURustExperimentTray', 'ConWU foreground')
        pid = c.c_ulong()
        if found:
            user.GetWindowThreadProcessId(found, c.byref(pid))
            if pid.value == process.pid:
                window = found
                break
        time.sleep(.1)
    assert window, 'Isolated tray window was not registered'
    ident = IDENT(); ident.cbSize = c.sizeof(ident); ident.hWnd = window; ident.uID = 1
    rectangle = RECT()
    def present():
        return shell.Shell_NotifyIconGetRect(c.byref(ident), c.byref(rectangle)) == 0
    deadline = time.monotonic()+5
    while not present() and time.monotonic() < deadline:
        time.sleep(.05)
    assert present(), 'Tray window exists without a shell icon'
    icon = ICON(); icon.cbSize = c.sizeof(icon); icon.hWnd = window; icon.uID = 1
    assert shell.Shell_NotifyIconW(2, c.byref(icon)), 'Could not simulate shell icon loss'
    assert not present(), 'Shell icon was not removed for the recovery check'
    message = user.RegisterWindowMessageW('TaskbarCreated')
    assert message and user.PostMessageW(window, message, 0, 0)
    deadline = time.monotonic()+5
    while not present() and time.monotonic() < deadline:
        time.sleep(.05)
    assert present(), 'ConWU did not restore its shell icon'
    proof = dict(realTrayRegistered=True, shellIconLossSimulated=True,
        taskbarCreatedRecovery=True, explorerProcessPreserved=True)
    (data/'result.json').write_text(json.dumps(proof, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(proof), flush=True)
finally:
    try:
        control = json.loads((data/'panel.private.json').read_text(encoding='utf-8'))
        request = urllib.request.Request(control['origin']+'/api/stop',
            json.dumps({'secret': control['secret']}).encode(),
            {'Content-Type': 'application/json', 'Origin': control['origin']})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=5):
            pass
    except Exception:
        pass
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.terminate(); process.wait(timeout=5)
