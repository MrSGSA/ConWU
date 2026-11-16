"""Reject a release that accidentally depends on the build host's loader/libc."""
import struct
import sys
from pathlib import Path
for name in sys.argv[1:]:
    data=Path(name).read_bytes()
    if data[:6]!=b'\x7fELF\x02\x01':raise ValueError(f'Not little-endian ELF64: {name}')
    offset=struct.unpack_from('<Q',data,32)[0]
    size,count=struct.unpack_from('<HH',data,54)
    for index in range(count):
        at=offset+index*size
        kind=struct.unpack_from('<I',data,at)[0]
        if kind==3:raise ValueError(f'Unexpected PT_INTERP in static release: {name}')
        if kind==2:
            start=struct.unpack_from('<Q',data,at+8)[0]
            length=struct.unpack_from('<Q',data,at+32)[0]
            for entry in range(start,start+length,16):
                tag,_=struct.unpack_from('<qQ',data,entry)
                if tag==1:raise ValueError(f'Unexpected DT_NEEDED in static release: {name}')
                if tag==0:break
    print(Path(name).name,'static ELF verified')
