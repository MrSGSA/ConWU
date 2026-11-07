#!/usr/bin/env python3
import pathlib,subprocess,sys,tempfile
mountpoint=pathlib.Path(tempfile.mkdtemp(prefix='conwu-empty-systemd-'))
subprocess.run(['mount','--bind',str(mountpoint),'/etc/systemd/system'],check=True)
subprocess.run([str(pathlib.Path(sys.argv[1]).resolve()),'--wal-foreground'],check=True)
