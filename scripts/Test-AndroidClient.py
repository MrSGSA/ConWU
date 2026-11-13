"""Own-emulator-only VPN smoke test. Never targets an attached physical phone."""
import argparse
import json
import pathlib
import re
import subprocess
import socket
import time
import xml.etree.ElementTree as ET

parser=argparse.ArgumentParser()
parser.add_argument('--adb',required=True)
parser.add_argument('--output',type=pathlib.Path,required=True)
parser.add_argument('--host',type=pathlib.Path,required=True)
parser.add_argument('--reinstall-apk',type=pathlib.Path)
parser.add_argument('--host-source',choices=['existing','autonomous'],default='existing')
parser.add_argument('--expect-version')
parser.add_argument('--check-unreachable',action='store_true')
args=parser.parse_args()
if args.output.exists() and any(args.output.iterdir()):raise RuntimeError('Use a fresh test evidence directory')
args.output.mkdir(parents=True,exist_ok=True)
app='io.github.mrsgsa.conwu'


def adb(*words,timeout=35,check=True):
    result=subprocess.run([args.adb,'-P','5038','-s','emulator-5580',*words],capture_output=True,timeout=timeout)
    if check and result.returncode:
        raise RuntimeError('Emulator command failed: '+result.stdout.decode(errors='replace')+result.stderr.decode(errors='replace'))
    return result.stdout.decode('utf-8',errors='replace').strip()


if adb('shell','getprop','ro.kernel.qemu')!='1':
    raise RuntimeError('This test only runs on its isolated emulator')
def version():
    details=adb('shell','dumpsys','package',app)
    return re.search(r'\bversionName=(\S+)',details).group(1)
initial_version=version()
adb('shell','pm','clear',app)
adb('shell','monkey','-p',app,'-c','android.intent.category.LAUNCHER','1')
time.sleep(3)


def tree():
    for _ in range(3):
        adb('shell','rm','-f','/data/local/tmp/conwu-test-ui.xml')
        adb('shell','uiautomator','dump','/data/local/tmp/conwu-test-ui.xml',timeout=25)
        content=adb('shell','cat','/data/local/tmp/conwu-test-ui.xml',check=False)
        if content.startswith('<?xml'):return ET.fromstring(content)
        time.sleep(1)
    raise RuntimeError('No fresh Android accessibility hierarchy; see screenshot/logcat evidence')


def tap(node):
    values=list(map(int,re.findall(r'\d+',node.attrib['bounds'])))
    adb('shell','input','tap',str((values[0]+values[2])//2),str((values[1]+values[3])//2))


def text_button(label):
    root=tree()
    node=next((n for n in root.iter('node') if n.attrib.get('text')==label and n.attrib.get('enabled')=='true'),None)
    if node is None:
        raise RuntimeError('Expected enabled emulator button: '+label)
    tap(node)


def wait(test,name,seconds=35):
    until=time.monotonic()+seconds
    while time.monotonic()<until:
        if test():
            print('PASS '+name,flush=True)
            return
        time.sleep(.4)
    raise RuntimeError('Timed out: '+name)


hosts=[]
reports=[]
try:
    wait(lambda:any(n.attrib.get('class')=='android.widget.EditText' for n in tree().iter('node')),'Android cold start finishes',seconds=45)
    wait(lambda:any(n.attrib.get('text')=='请求加入' and n.attrib.get('enabled')=='true' for n in tree().iter('node')),'device identity loads without blocking the window',seconds=45)
    for mode in ['tcp','https']:
        folder=args.output/mode
        folder.mkdir(exist_ok=True)
        log=(folder/'host.log').open('wb')
        host=subprocess.Popen(['dotnet',str(args.host.resolve()),'--android-host',str(folder.resolve()),mode]+(['autonomous'] if args.host_source=='autonomous' else []),stdout=log,stderr=log,creationflags=subprocess.CREATE_NO_WINDOW)
        hosts.append((host,log))
        state_path=folder/'host.json'
        wait(lambda:state_path.exists(),'isolated '+mode+' host is ready')
        def state():return json.loads(state_path.read_text())
        code=state()['code']
        if not re.fullmatch(r'[0-9A-HJKMNP-TV-Z-]{19}',code):raise RuntimeError('Fixture direct code shape mismatch')
        root=tree();field=next(n for n in root.iter('node') if n.attrib.get('class')=='android.widget.EditText')
        tap(field);adb('shell','input','keycombination','KEYCODE_CTRL_LEFT','KEYCODE_A')
        adb('shell','input','keyevent','KEYCODE_DEL')
        adb('shell','input','text',code)
        adb('shell','input','keyevent','KEYCODE_BACK')
        text_button('请求加入')
        time.sleep(1)
        root=tree()
        for node in root.iter('node'):
            if node.attrib.get('package')=='com.android.vpndialogs' and node.attrib.get('resource-id')=='android:id/button1':tap(node);break
        wait(lambda:bool(state()['verification']),'host sees the committed mobile key exchange')
        verification=state()['verification']
        wait(lambda:any(verification in n.attrib.get('text','') for n in tree().iter('node')),'Android and host display the same verification code',seconds=12)
        wait(lambda:state()['connected'],'Android '+mode+' VPN member authenticates',seconds=35)
        peer=state()['virtualIp']
        (folder/'route.txt').write_text(adb('shell','ip','route','get',peer,check=False),encoding='utf-8')
        result=adb('shell','ping','-c','3','-W','2',peer,timeout=12,check=False)
        if not re.search(r'\b0% packet loss',result):raise RuntimeError('Kernel VPN ping failed: '+result)
        (folder/'ping.txt').write_text(result,encoding='utf-8')
        message=b'ConWU kernel UDP test\x00\x01\xff';before_packets=state()['packets']
        echo=subprocess.run([args.adb,'-P','5038','-s','emulator-5580','shell','-T','toybox','nc','-u','-n','-w','3','-W','2','-q','2',peer,'45124'],input=message,capture_output=True,timeout=10)
        if message not in echo.stdout or state()['packets']<=before_packets:raise RuntimeError('Android OS UDP socket received no valid host echo: '+repr(echo.stdout)+echo.stderr.decode(errors='replace'))
        (folder/'udp-echo.bin').write_bytes(echo.stdout)
        report={'protocol':mode,'verificationMatched':True,'kernelVirtualIpPing':True,'kernelUdpEcho':True,'hostAuthenticated':True}
        reports.append(report)
        print('PASS system VPN carries authenticated '+mode+' ICMP packets',flush=True)
    adb('shell','am','force-stop',app)
    time.sleep(1)
    adb('shell','monkey','-p',app,'-c','android.intent.category.LAUNCHER','1')
    for mode in ['tcp','https']:
        state_path=args.output/mode/'host.json'
        wait(lambda:json.loads(state_path.read_text())['connected'],'encrypted '+mode+' membership reconnects after Android process restart',seconds=40)
        peer=json.loads(state_path.read_text())['virtualIp']
        result=adb('shell','ping','-c','2','-W','2',peer,timeout=10)
        if not re.search(r'\b0% packet loss',result):raise RuntimeError('Post-restart VPN ping failed: '+result)
    if args.reinstall_apk:
        adb('install','-r',str(args.reinstall_apk.resolve()),timeout=90)
        adb('shell','monkey','-p',app,'-c','android.intent.category.LAUNCHER','1')
        for mode in ['tcp','https']:
            state_path=args.output/mode/'host.json'
            wait(lambda:json.loads(state_path.read_text())['connected'],'same-signed APK replacement preserves '+mode+' credentials',seconds=40)
            peer=json.loads(state_path.read_text())['virtualIp']
            result=adb('shell','ping','-c','2','-W','2',peer,timeout=10)
            if not re.search(r'\b0% packet loss',result):raise RuntimeError('Post-install VPN ping failed: '+result)
    if args.check_unreachable:
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1',0));closed_port=reserve.getsockname()[1]
        bad_code=subprocess.check_output(['dotnet',str(args.host.resolve()),'--make-code','https','10.0.2.2:'+str(closed_port)],text=True).strip()
        root=tree();field=next(n for n in root.iter('node') if n.attrib.get('class')=='android.widget.EditText')
        tap(field);adb('shell','input','keycombination','KEYCODE_CTRL_LEFT','KEYCODE_A');adb('shell','input','keyevent','KEYCODE_DEL')
        adb('shell','input','text',bad_code);adb('shell','input','keyevent','KEYCODE_BACK');text_button('请求加入')
        wait(lambda:any('TCP 入口' in n.attrib.get('text','') for n in tree().iter('node')),'unreachable entry displays the TCP-stage diagnosis on Android',seconds=20)
        for mode in ['tcp','https']:
            peer=json.loads((args.output/mode/'host.json').read_text())['virtualIp']
            ping=adb('shell','ping','-c','2','-W','2',peer,timeout=10)
            if not re.search(r'\b0% packet loss',ping):raise RuntimeError('Failed join disrupted an existing network')
    (args.output/'connected-ui.xml').write_text(ET.tostring(tree(),encoding='unicode'),encoding='utf-8')
    capture=subprocess.run([args.adb,'-P','5038','-s','emulator-5580','exec-out','screencap','-p'],capture_output=True,timeout=15)
    (args.output/'connected.png').write_bytes(capture.stdout)
    final_version=version()
    if args.expect_version and final_version!=args.expect_version:raise RuntimeError('Wrong APK version after replacement')
    result={'status':'Pass','platform':'Android 15 x86_64 emulator','networks':reports,'processRestartPreservedCredentials':True,
            'initialVersion':initial_version,'finalVersion':final_version,'hostConfiguration':args.host_source,
            'unreachableEntryDiagnosisAndExistingNetworksPreserved':args.check_unreachable,
            'sameSignedReinstallPreservedCredentials':bool(args.reinstall_apk),
            'simultaneousNetworks':2,'physicalPhoneOrMoonlightTested':False,'productionServicesModified':False}
    (args.output/'result.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result),flush=True)
except BaseException:
    try:(args.output/'failure-ui.xml').write_text(ET.tostring(tree(),encoding='unicode'),encoding='utf-8')
    except Exception as error:print('UI evidence unavailable: '+str(error),flush=True)
    try:
        (args.output/'failure-logcat.txt').write_text(adb('logcat','-d','-t','2500'),encoding='utf-8')
        capture=subprocess.run([args.adb,'-P','5038','-s','emulator-5580','exec-out','screencap','-p'],capture_output=True,timeout=15)
        (args.output/'failure.png').write_bytes(capture.stdout)
    except Exception as error:print('Evidence capture failed: '+str(error),flush=True)
    raise
finally:
    adb('shell','am','force-stop',app,check=False)
    for host,log in reversed(hosts):
        host.terminate()
        try:host.wait(timeout=10)
        except subprocess.TimeoutExpired:host.kill();host.wait(timeout=10)
        log.close()
