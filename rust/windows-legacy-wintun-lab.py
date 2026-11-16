"""Real .NET -> Rust -> .NET Wintun handoff with a fresh synthetic identity.

Never stops a daily service, imports a daily network or removes a driver.
The original and Rust adapter implementations must share their ownership lease
and generation journal, including the period needed for installer rollback.
"""
import argparse
import ctypes
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess
import uuid

ROOT = Path(__file__).resolve().parent.parent


def powershell(code):
    return subprocess.check_output(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', code], text=True, encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app', type=Path, default=ROOT / 'out/rust-target/debug/conwu.exe')
    parser.add_argument('--oracle', type=Path, default=ROOT / 'out/rust-legacy-oracle/ConWU.DotnetOracle.dll')
    parser.add_argument('--components', type=Path, default=Path(os.environ['ProgramFiles']) / 'StreamLink/app/components')
    args = parser.parse_args()
    assert ctypes.windll.shell32.IsUserAnAdmin()
    info = json.loads(subprocess.check_output([str(args.app), 'build-info'], text=True))
    assert info['labApi'] and not info['production']
    service_pid = powershell("(Get-CimInstance Win32_Service -Filter \"Name='StreamLink-PersonalFeature'\").ProcessId").strip()
    addresses = json.loads(powershell('Get-NetIPAddress -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress | ConvertTo-Json -Compress'))
    routes = json.loads(powershell('Get-NetRoute -AddressFamily IPv4 | Select-Object -ExpandProperty DestinationPrefix | ConvertTo-Json -Compress'))
    occupied = [ipaddress.ip_network(value + '/24', strict=False) for value in addresses]
    occupied += [ipaddress.ip_network(value, strict=False) for value in routes if ipaddress.ip_network(value, strict=False).prefixlen >= 24]
    for _ in range(100):
        address = f'10.{200 + secrets.randbelow(51)}.{1 + secrets.randbelow(254)}.1'
        prefix = ipaddress.ip_network(address + '/24', strict=False)
        if not any(prefix.overlaps(other) for other in occupied):
            break
    else:
        raise RuntimeError('No isolated virtual subnet found')
    network, owner = uuid.uuid4().hex, uuid.uuid4().hex
    folder = ROOT / 'out/lab' / ('wintun-handoff-' + uuid.uuid4().hex)
    folder.mkdir(parents=True)
    oracle_log = (folder / 'oracle.log').open('wb')
    rust_log = (folder / 'rust.log').open('wb')
    oracle = subprocess.Popen(['dotnet', str(args.oracle)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=oracle_log, text=True, encoding='utf-8', creationflags=subprocess.CREATE_NO_WINDOW)
    rust = None
    request = dict(op='wintun-open', components=str(args.components), network=network, owner=owner, address=address)
    def call(body):
        oracle.stdin.write(json.dumps(body) + '\n')
        oracle.stdin.flush()
        line = oracle.stdout.readline()
        if not line:
            raise RuntimeError('Legacy oracle exited; inspect the isolated oracle log')
        return json.loads(line)
    try:
        opened = call(request)
        assert opened['ok'], opened.get('error')
        scope = opened['result']['scope']
        assert call(dict(op='wintun-close'))['ok']
        print(json.dumps(dict(legacyAdapterCreatedAndClosed=True)), flush=True)
        rust = subprocess.Popen([str(args.app), 'lab-wintun', '--network', network, '--owner', owner,
                                 '--address', address, '--components', str(args.components)], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=rust_log, text=True, encoding='utf-8', creationflags=subprocess.CREATE_NO_WINDOW)
        ready = json.loads(rust.stdout.readline())
        assert ready['ready'] and ready['provider'] == 'Official.Wintun'
        journal_path = Path(os.environ['ProgramData']) / 'StreamLink-Wintun' / (scope.replace('-', '') + '-adapters.json')
        rust_journal = Path(os.environ['ProgramData']) / 'ConWU-Wintun' / network / 'generation.json'
        generation = json.loads(rust_journal.read_text())
        journal = json.loads(journal_path.read_text())
        assert generation['id'] in journal['Generations']
        assert generation['name'] == 'StreamLink-' + owner[:8] + '-1-' + generation['id'].replace('-', '')
        refused = call(request)
        assert not refused['ok'] and '仍由其他实例持有' in refused['error'], 'Legacy instance bypassed the Rust ownership lease'
        rust.stdin.write('stop\n')
        rust.stdin.flush()
        assert rust.wait(timeout=90) == 0
        assert json.loads(journal_path.read_text())['LastClosedAt'] > 0
        print(json.dumps(dict(rustHandoff=True, originalJournalShared=True, concurrentLegacyOwnerDenied=True)), flush=True)
        reopened = call(request)
        assert reopened['ok'], reopened.get('error')
        assert call(dict(op='wintun-close'))['ok']
        assert powershell("(Get-CimInstance Win32_Service -Filter \"Name='StreamLink-PersonalFeature'\").ProcessId").strip() == service_pid
        evidence = dict(dotnetToRust=True, rustToDotnet=True, originalJournalShared=True, ownerLeaseShared=True,
                        sameVirtualIp=True, officialWintun=True, productionProcessUnchanged=True)
        (ROOT / 'out/parity-windows-legacy-wintun-result.json').write_text(json.dumps(evidence, indent=2))
        print(json.dumps(evidence), flush=True)
    finally:
        if rust is not None and rust.poll() is None:
            try:
                rust.stdin.write('stop\n'); rust.stdin.flush(); rust.wait(timeout=90)
            except (OSError, subprocess.TimeoutExpired):
                rust.terminate(); rust.wait(timeout=10)
        if oracle.poll() is None:
            oracle.stdin.close()
            try: oracle.wait(timeout=90)
            except subprocess.TimeoutExpired: oracle.terminate(); oracle.wait(timeout=10)
        oracle_log.close()
        rust_log.close()


if __name__ == '__main__':
    main()
