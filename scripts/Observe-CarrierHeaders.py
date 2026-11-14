"""Bounded, sniff-only WinDivert counters for one isolated carrier port.

Only IP/TCP header sizes, flags and counters are retained. Payload bytes are
never printed or written. The original packets continue through the stack.
Configuration and status commands use stdin, like the native test nodes.
"""
import collections
import ctypes
import ipaddress
import json
import os
import sys
import threading


def main():
    config = json.loads(sys.stdin.readline())
    address = str(ipaddress.IPv4Address(config["Address"]))
    port = int(config["Port"])
    if not 1024 <= port <= 65535:
        raise ValueError("isolated non-privileged port required")
    outbound = bool(config.get("Outbound"))
    expression = f"{'outbound' if outbound else 'inbound'} and ip and tcp and ip.SrcAddr == {address} and tcp.SrcPort == {port}"
    api = ctypes.WinDLL(config["Dll"], use_last_error=True)
    api.WinDivertOpen.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_short, ctypes.c_uint64]
    api.WinDivertOpen.restype = ctypes.c_void_p
    api.WinDivertRecv.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.POINTER(ctypes.c_uint), ctypes.c_void_p]
    api.WinDivertRecv.restype = ctypes.c_bool
    api.WinDivertSetParam.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint64]
    api.WinDivertSetParam.restype = ctypes.c_bool
    api.WinDivertShutdown.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    api.WinDivertClose.argtypes = [ctypes.c_void_p]
    # Injected outbound packets resume below their producing handle. Inbound
    # observation must precede the carrier's consuming handle instead.
    handle = api.WinDivertOpen(expression.encode("ascii"), 0, -30000 if outbound else 30000, 1 | 4)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    lock, stopped = threading.Lock(), threading.Event()
    frequency = ctypes.c_longlong()
    ctypes.windll.kernel32.QueryPerformanceFrequency(ctypes.byref(frequency))
    counts = collections.Counter()
    lengths, payloads = collections.Counter(), collections.Counter()
    buckets = collections.Counter()
    def capture():
        packet, metadata, size = ctypes.create_string_buffer(65535), ctypes.create_string_buffer(80), ctypes.c_uint()
        while not stopped.is_set():
            if not api.WinDivertRecv(handle, packet, len(packet), ctypes.byref(size), metadata):
                if not stopped.is_set():
                    with lock:
                        counts["captureError"] = ctypes.get_last_error()
                break
            header = packet.raw[:min(size.value, 60)]
            if len(header) < 40 or header[0] >> 4 != 4:
                continue
            ihl = (header[0] & 15) * 4
            if len(header) < ihl + 20:
                continue
            total = int.from_bytes(header[2:4], "big")
            tcp = (header[ihl + 12] >> 4) * 4
            payload = max(0, total - ihl - tcp)
            with lock:
                counts["packets"] += 1
                counts["ipBytes"] += size.value
                counts["oversizedPackets"] += size.value > 1500
                counts["pshPackets"] += bool(header[ihl + 13] & 8)
                if payload >= 1000:
                    counts["bulkPackets"] += 1
                    counts["bulkPayloadBytes"] += payload
                    lengths[size.value] += 1
                    payloads[payload] += 1
                    stamp = int.from_bytes(metadata.raw[:8], "little", signed=True)
                    bucket = stamp * 1000 // frequency.value
                    buckets[bucket] += 1
                    counts["maxBulkPacketsPer1ms"] = max(counts["maxBulkPacketsPer1ms"], buckets[bucket])
    def snapshot():
        with lock:
            return {**counts, "bulkIpLengths": dict(lengths), "bulkPayloadLengths": dict(payloads),
                    "captureLossAccountingAvailable": False,
                    "comparisonProvesWireLoss": False}
    thread = threading.Thread(target=capture, daemon=True)
    deadline = threading.Timer(180, lambda: os._exit(3))
    deadline.daemon = True
    try:
        # A 100 ms observation queue can expire during an ordinary scheduling
        # pause. More headroom does not establish capture completeness: this
        # WinDivert API does not expose an observer loss counter. Counts are
        # observed lower bounds and cannot independently locate wire loss.
        for key, value in ((0, 4096), (1, 2000), (2, 32 << 20)):
            if not api.WinDivertSetParam(handle, key, value):
                raise ctypes.WinError(ctypes.get_last_error())
        thread.start()
        deadline.start()
        print(json.dumps({"eventName": "ready", "pid": os.getpid(), "sniffOnly": True}), flush=True)
        for line in sys.stdin:
            action = json.loads(line)["action"]
            if action == "stop":
                print(json.dumps({"eventName": "stopping"}), flush=True)
                break
            if action == "reset":
                with lock:
                    counts.clear()
                    lengths.clear()
                    payloads.clear()
                    buckets.clear()
            print(json.dumps({"eventName": action, "stats": snapshot()}), flush=True)
    finally:
        stopped.set()
        api.WinDivertShutdown(handle, 3)
        if thread.is_alive():
            thread.join(timeout=3)
        api.WinDivertClose(handle)
        deadline.cancel()


if __name__ == "__main__":
    main()
