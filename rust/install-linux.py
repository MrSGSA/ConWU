"""Install the verified Rust bundle with a complete previous-version snapshot.

The validation option is accepted only by a non-production candidate, uses the
reserved experimental unit and never touches production paths or CLI links.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import time
import uuid

PRODUCT = '{AD076018-A9B8-47F5-B098-97479A363416}'
MARKER = '# ConWU Rust managed unit'


def require(value, message='安装资料或路径不符合预期'):
    if not value:
        raise ValueError(message)


def check_path(path):
    path = Path(os.path.abspath(path))
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError('安装路径不能包含符号链接：' + str(part))
    return path


def copy_tree(source, destination, settings=False):
    check_path(source)
    check_path(destination)
    require(not destination.exists() and not destination.is_relative_to(source), '快照目录存在或与来源重叠')
    destination.mkdir(parents=True, mode=0o700 if settings else 0o755)
    count = total = 0
    for parent, dirs, files in os.walk(source, followlinks=False):
        parent = Path(parent)
        if settings and parent == source:
            dirs[:] = [d for d in dirs if d not in ('updates', 'update-rollback', 'maintenance', 'logs')]
        for name in dirs:
            check_path(parent / name)
            (destination / (parent / name).relative_to(source)).mkdir(mode=0o700 if settings else 0o755)
        for name in files:
            if settings and parent == source and (name in ('instance.lock', 'runtime.lock', 'control.sock', 'panel.private.json', 'lab-session.private.json') or name.endswith('.tmp')):
                continue
            path = check_path(parent / name)
            metadata = path.stat()
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError('安装资料包含非普通文件')
            count += 1
            total += metadata.st_size
            if count > 16384 or total > 2 * 1024**3:
                raise ValueError('安装快照超过容量限制')
            shutil.copy2(path, destination / path.relative_to(source))


def remove_owned(path, prefix, product=PRODUCT):
    check_path(path)
    require(path.is_relative_to(prefix) and path != prefix, '拒绝越界清理安装目录')
    if not path.exists():
        return
    marker = json.loads((path / '.conwu-rust-package').read_text())
    require(marker['product'] == product, '回退目录不属于本产品')
    for parent, dirs, files in os.walk(path, followlinks=False):
        for name in dirs + files:
            check_path(Path(parent) / name)
    shutil.rmtree(path)


def command(*args, check=True, timeout=90):
    return subprocess.run(args, capture_output=True, text=True, check=check, timeout=timeout)


def wait_ready(executable, data, unit_name, version=None):
    deadline = time.monotonic() + 240
    while True:
        try:
            state = json.loads(command(str(executable), '--data', str(data), 'status', timeout=15).stdout)
            adapters = all(n['enabled'] is not True or not n['status'].get('networkId') or n['status']['adapter']['ready'] for n in state['networks'])
            coordinator = state['deviceSettings']['coordinator']['enabled'] is not True or state['coordinator']['running']
            if (version is None or state['version'] == version) and adapters and coordinator:
                return
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
            pass
        if command('systemctl', 'show', unit_name, '--property=ActiveState', '--value').stdout.strip() == 'failed':
            raise RuntimeError('后台启动失败')
        if time.monotonic() > deadline:
            raise TimeoutError('后台、虚拟网卡或协调服务未就绪')
        time.sleep(.5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-start', action='store_true')
    parser.add_argument('--uninstall', action='store_true')
    parser.add_argument('--validation-root', type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('请使用 sudo ./install.sh')
    bundle = check_path(Path(__file__).parent)
    info = json.loads(command(str(bundle / 'conwu'), 'build-info').stdout)
    manifest = json.loads((bundle / '.conwu-rust-package').read_text())
    require(info['localInstall'] and not info['labApi'] and info['platform'] == 'linux' and info['architecture'] == 'x86_64')
    require(manifest['product'] == info['product'] and manifest['version'] == info['version'])
    require(manifest['os'] == 'linux' and manifest['arch'] == 'x86_64')
    entries = (bundle / 'SHA256SUMS').read_text().splitlines()
    require(3 <= len(entries) <= 4096)
    seen = set()
    for line in entries:
        digest, relative = line.split('  ', 1)
        path = Path(relative)
        require(not path.is_absolute() and '..' not in path.parts and relative not in seen)
        seen.add(relative)
        candidate = check_path(bundle / path)
        require(candidate.is_file() and hashlib.sha256(candidate.read_bytes()).hexdigest() == digest, '安装文件校验失败：' + relative)
    require({'conwu', '.conwu-rust-package', 'install.py'} <= seen)
    for tool in ('systemctl', 'systemd-run'):
        require(shutil.which(tool), '缺少安装依赖：' + tool)
    validation = args.validation_root is not None
    if validation:
        require(not info['production'], '正式包不能使用实验安装路径')
        root = check_path(args.validation_root)
        require(root.name.startswith('conwu-install-validation-'))
        uuid.UUID(hex=root.name.removeprefix('conwu-install-validation-'))
        prefix, data, legacy = root / 'program', root / 'data', None
        cli = root / 'bin'
        unit_name = 'conwu-rust-experiment.service'
        unit = Path('/run/systemd/system') / unit_name
        state = command('systemctl', 'show', unit_name, '--property=LoadState', '--value', check=False).stdout.strip()
        require(state == 'not-found' or (unit.is_file() and str(prefix) in unit.read_text()), '实验服务名已被占用')
    else:
        require(info['production'] and info['product'] == PRODUCT, '请使用正式构建的 Linux 包')
        prefix, data, legacy, cli = Path('/opt/conwu'), Path('/var/lib/conwu'), Path('/var/lib/streamlink'), Path('/usr/local/bin')
        unit_name = 'streamlink.service'
        unit = Path('/etc/systemd/system') / unit_name
    for path in (prefix, data, cli, unit):
        check_path(path)
    if data.is_dir() and any(data.iterdir()):
        require((data / '.conwu-rust-owned').is_file(), '新资料目录已被其他程序使用')
    prefix.mkdir(parents=True, mode=0o755, exist_ok=True)
    data.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(data, 0o700)
    if not (data / '.conwu-rust-owned').exists():
        (data / '.conwu-rust-owned').write_bytes(b'ConWU Rust experimental data v1\n')
    lock_path = check_path(prefix / 'install.lock')
    with lock_path.open('a') as lease:
        fcntl.flock(lease.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.uninstall:
            uninstall(info, prefix, data, cli, unit, unit_name, validation)
        else:
            install(bundle, info, prefix, data, legacy, cli, unit, unit_name, args.no_start, validation)


def uninstall(info, prefix, data, cli, unit, unit_name, validation):
    require(unit.is_file() and MARKER in unit.read_text().splitlines(), '未找到本安装器创建的 Rust 服务')
    current = prefix / 'current'
    require(str(current / 'conwu') in unit.read_text(), '服务运行目录不符合预期')
    require(json.loads((current / '.conwu-rust-package').read_text())['product'] == info['product'])
    command('systemctl', 'stop', unit_name)
    if not validation:
        command('systemctl', 'disable', unit_name)
    unit.unlink()
    command('systemctl', 'daemon-reload')
    for name in ('conwu', 'streamlink'):
        path = cli / name
        if path.is_symlink() and os.readlink(path) == str(current / 'conwu'):
            path.unlink()
    for name in ('current', 'conwu-rust-previous'):
        remove_owned(prefix / name, prefix, info['product'])
    print('ConWU 程序已卸载，设置、身份和日志保留在 ' + str(data))


def install(bundle, info, prefix, data, legacy, cli, unit, unit_name, no_start, validation):
    current, previous, staging = (prefix / n for n in ('current', 'conwu-rust-previous', 'conwu-rust-next'))
    for path in (current, previous, staging):
        check_path(path)
    old_unit = unit.read_bytes() if unit.is_file() else None
    if old_unit:
        lines = old_unit.decode().splitlines()
        require(MARKER in lines or '# StreamLink managed unit' in lines, '同名服务不属于 ConWU，已停止安装')
        start = next(line.removeprefix('ExecStart=') for line in lines if line.startswith('ExecStart='))
        executable = shlex.split(start)[0]
        require(executable in (str(current / 'conwu'), '/opt/streamlink/current/streamlink'), '服务运行路径不符合预期')
    if current.exists():
        require(json.loads((current / '.conwu-rust-package').read_text())['product'] == info['product'])
    if staging.exists():
        raise RuntimeError('存在未完成安装目录，请先核对：' + str(staging))
    for name in ('conwu', 'streamlink'):
        link = cli / name
        if link.exists() or link.is_symlink():
            require(link.is_symlink() and os.readlink(link) in (str(current / 'conwu'), '/opt/streamlink/current/streamlink'), '命令路径已被其他程序占用')
    active = command('systemctl', 'is-active', '--quiet', unit_name, check=False).returncode == 0
    enabled = command('systemctl', 'is-enabled', '--quiet', unit_name, check=False).returncode == 0 if old_unit else not validation
    copy_tree(bundle, staging)
    if old_unit:
        command('systemctl', 'stop', unit_name)
    swapped = False
    try:
        if previous.exists():
            remove_owned(previous, prefix, info['product'])
        if current.exists():
            current.rename(previous)
        elif old_unit and not validation:
            old_program = Path('/opt/streamlink/current').resolve(strict=True)
            require(old_program.is_relative_to(Path('/opt/streamlink/releases')))
            copy_tree(check_path(old_program), previous)
            (previous / '.conwu-rust-package').write_text(json.dumps(dict(product=PRODUCT, version='legacy-dotnet', os='linux', arch='x86_64', format='dotnet-migration-backup')))
        staging.rename(current)
        swapped = True
        rollback = data / 'update-rollback'
        if rollback.exists():
            check_path(rollback)
            require((data / '.conwu-rust-owned').is_file())
            for parent, dirs, files in os.walk(rollback, followlinks=False):
                for name in dirs + files:
                    check_path(Path(parent) / name)
            shutil.rmtree(rollback)
        rollback.mkdir(mode=0o700)
        (rollback / '.conwu-rust-package').write_text(json.dumps(dict(product=info['product'])))
        if old_unit:
            (rollback / 'service.unit').write_bytes(old_unit)
        source = data if (data / 'database.private.json').exists() else legacy
        if source is not None and source.exists():
            # Snapshot outside the source before returning it to the fixed data
            # rollback location; never recursively copy the snapshot itself.
            temporary = prefix / ('settings-' + uuid.uuid4().hex)
            copy_tree(check_path(source), temporary, settings=True)
            temporary.rename(rollback / 'settings')
        if not (data / 'database.private.json').is_file() and legacy is not None and (legacy / 'profile.json').is_file():
            command(str(current / 'conwu'), 'migrate', '--from', str(legacy), '--data', str(data))
        quote = lambda path: '"' + str(path).replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%') + '"'
        text = MARKER + '\n[Unit]\nDescription=ConWU Network\nAfter=network.target\nStartLimitIntervalSec=30\nStartLimitBurst=3\n[Service]\nExecStart=' + quote(current / 'conwu') + ' run --data ' + quote(data) + ' --components ' + quote(current / 'components') + ' --no-open --no-tray\nRestart=on-failure\nRestartSec=2\nKillMode=control-group\n[Install]\nWantedBy=multi-user.target\n'
        unit.write_text(text)
        os.chmod(unit, 0o644)
        command('systemctl', 'daemon-reload')
        state = command('systemctl', 'show', unit_name, '--property=ActiveState', '--value').stdout.strip()
        if state == 'failed':
            command('systemctl', 'reset-failed', unit_name)
        if not no_start and (active or not old_unit):
            command('systemctl', 'start', unit_name)
            wait_ready(current / 'conwu', data, unit_name, info['version'])
        if not validation:
            command('systemctl', 'enable' if enabled else 'disable', unit_name)
        cli.mkdir(parents=True, exist_ok=True)
        for name in ('conwu', 'streamlink'):
            target = cli / name
            temporary = cli / ('.conwu-install-' + uuid.uuid4().hex)
            temporary.symlink_to(current / 'conwu')
            os.replace(temporary, target)
    except BaseException:
        command('systemctl', 'stop', unit_name, check=False)
        if swapped:
            failed = prefix / ('failed-' + uuid.uuid4().hex)
            current.rename(failed)
            if previous.exists():
                previous.rename(current)
        elif not current.exists() and previous.exists() and old_unit and str(current / 'conwu') in old_unit.decode():
            previous.rename(current)
        if old_unit:
            unit.write_bytes(old_unit)
        elif unit.exists() and MARKER in unit.read_text():
            unit.unlink()
        command('systemctl', 'daemon-reload')
        if active:
            command('systemctl', 'reset-failed', unit_name, check=False)
            command('systemctl', 'start', unit_name)
            if str(current / 'conwu') in old_unit.decode():
                prior_version = json.loads((current / '.conwu-rust-package').read_text())['version']
                wait_ready(current / 'conwu', data, unit_name, prior_version)
            elif legacy is not None:
                wait_ready(Path('/opt/streamlink/current/streamlink'), legacy, unit_name)
        raise
    print('ConWU ' + info['version'] + ' 已安装，设置和网络身份已保留。')
    print('查看状态：sudo conwu status；打开面板：sudo conwu panel')


if __name__ == '__main__':
    main()
