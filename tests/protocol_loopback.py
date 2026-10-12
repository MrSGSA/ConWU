"""Exercise the real C++ protocol and event loops without WinDivert or a driver.

Only udp2raw-protocol-test.exe implements the loopback raw-packet I/O used here.
These results are protocol regressions, NOT Internet/QoS/driver benchmarks.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import select
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "out/native/udp2raw-protocol-test.exe"
HTTP_SEQUENCE_PROFILE = {}


def udp_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    return sock


def free_port(kind=socket.SOCK_DGRAM):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def tcp_payload(packet):
    if len(packet) < 40 or packet[0] >> 4 != 4:
        return b""
    ip_len = (packet[0] & 15) * 4
    if packet[9] == 17:
        return packet[ip_len + 8:]
    if ip_len < 20 or len(packet) < ip_len + 20:
        return b""
    tcp_len = (packet[ip_len + 12] >> 4) * 4
    return packet[ip_len + tcp_len:]


def corrupt_authenticated_payload(packet):
    data = bytearray(packet)
    data[-1] ^= 0x40
    ip_len = (data[0] & 15) * 4
    data[ip_len + 16:ip_len + 18] = b"\0\0"
    pseudo = bytes(data[12:20]) + b"\0\x06" + struct.pack("!H", len(data) - ip_len)
    checked = pseudo + bytes(data[ip_len:])
    if len(checked) % 2:
        checked += b"\0"
    total = sum(struct.unpack(f"!{len(checked)//2}H", checked))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    data[ip_len + 16:ip_len + 18] = struct.pack("!H", (~total) & 65535)
    return bytes(data)


class Tunnel:
    def __init__(self, http=True, wrong_key=False, raw_mode="faketcp", udp_shape=False, wire_ids=None, closed_report_sink=False):
        self.directory = tempfile.TemporaryDirectory(prefix="streamlink-protocol-")
        self.path = Path(self.directory.name)
        self.stop = threading.Event()
        self.processes = []
        self.files = []
        self.sockets = []
        self.thread = None
        self.http_seen = False
        # Bounded metadata only: freeze the existing handshake wire profile
        # before adding simultaneous-open. Never record keys or data payloads.
        self.wire = []
        self.wire_lock = threading.Lock()
        self.stun_seen = False
        self.mode = None
        self.held = None
        self.altered = threading.Event()
        self.key = secrets.token_hex(32)
        try:
            self.proxy_c, self.proxy_s, self.echo = [udp_socket() for _ in range(3)]
            self.sockets.extend((self.proxy_c, self.proxy_s, self.echo))
            self.client_wire, self.server_wire = free_port(), free_port()
            self.client_app = free_port()
            self.server_raw = free_port(socket.SOCK_DGRAM if raw_mode == "udp" else socket.SOCK_STREAM)
            common = [f"--raw-mode {raw_mode}", "--fix-gro", "--seq-mode 3", "--hb-mode 0", "--log-level 4"]
            if closed_report_sink:
                common[-1] = "--log-level 0"
            if http:
                common.append("--fake-http test.ustc.edu.cn")
            server = ["-s", f"-l 127.0.0.1:{self.server_raw}", f"-r 127.0.0.1:{self.echo.getsockname()[1]}", f"-k {self.key}"] + common
            client = ["-c", f"-l 127.0.0.1:{self.client_app}", f"-r 127.0.0.1:{self.server_raw}", f"-k {secrets.token_hex(32) if wrong_key else self.key}"] + common
            for name, config, port, peer in (
                ("server", server, self.server_wire, self.proxy_s.getsockname()[1]),
                ("client", client, self.client_wire, self.proxy_c.getsockname()[1]),
            ):
                config_file = self.path / f"{name}.conf"
                config_file.write_text("\n".join(config), encoding="ascii")
                log = (self.path / f"{name}.log").open("wb")
                self.files.append(log)
                env = dict(os.environ, STREAMLINK_TEST_BIND=str(port), STREAMLINK_TEST_PEER=str(peer))
                env.pop('STREAMLINK_LEGACY_WIRE_ID', None)
                if wire_ids is not None:
                    env['STREAMLINK_LEGACY_WIRE_ID'] = wire_ids[name]
                env['STREAMLINK_UDP_SHAPE'] = 'stun' if udp_shape else ''
                self.processes.append(subprocess.Popen([str(EXE), "--conf-file", str(config_file)],
                    stdout=subprocess.PIPE if closed_report_sink else log,
                    stderr=log if closed_report_sink else subprocess.STDOUT, env=env, creationflags=subprocess.CREATE_NO_WINDOW))
                if closed_report_sink:
                    self.processes[-1].stdout.close()
            self.thread = threading.Thread(target=self.pump, daemon=True)
            self.thread.start()
            self.app = udp_socket()
            self.sockets.append(self.app)
            self.app.connect(("127.0.0.1", self.client_app))
            self.app.settimeout(0.1)
        except BaseException:
            self.close()
            raise

    def pump(self):
        while not self.stop.is_set():
            ready, _, _ = select.select([self.proxy_c, self.proxy_s, self.echo], [], [], 0.02)
            for sock in ready:
                try:
                    packet, peer = sock.recvfrom(65535)
                except ConnectionResetError:
                    # Windows reports an earlier UDP ICMP port-unreachable here
                    # if the peer process has not yet bound during startup.
                    # Keep the proxy alive; the readiness deadline still fails
                    # the test if the real protocol never becomes functional.
                    continue
                if sock is self.echo:
                    sock.sendto(packet, peer)
                    continue
                expected = self.client_wire if sock is self.proxy_c else self.server_wire
                if peer != ("127.0.0.1", expected):
                    continue
                destination = self.server_wire if sock is self.proxy_c else self.client_wire
                output = self.proxy_s if sock is self.proxy_c else self.proxy_c
                payload = tcp_payload(packet)
                if len(packet) >= 40 and packet[9] == 6:
                    ihl = (packet[0] & 15) * 4
                    if ihl >= 20 and len(packet) >= ihl + 20:
                        source_port, destination_port, seq, ack = struct.unpack_from("!HHII", packet, ihl)
                        with self.wire_lock:
                            if len(self.wire) < 512:
                                self.wire.append(dict(side="client" if sock is self.proxy_c else "server",
                                    source_ip=socket.inet_ntoa(packet[12:16]), source_port=source_port, destination_port=destination_port,
                                    at=time.monotonic(), flags=packet[ihl + 13], seq=seq, ack=ack,
                                    payload_bytes=len(payload), http=payload.startswith(b"GET / HTTP/1.1\r\n")))
                if payload[:2] == b'\x00\x17' and payload[4:8] == b'\x21\x12\xa4\x42':
                    self.stun_seen = True
                if b"Host: test.ustc.edu.cn\r\n" in payload:
                    self.http_seen = True
                if sock is self.proxy_c and len(payload) > 500:
                    if self.mode == "drop":
                        self.mode = None
                        self.altered.set()
                        continue
                    if self.mode == "corrupt":
                        self.mode = None
                        packet = corrupt_authenticated_payload(packet)
                        self.altered.set()
                    elif self.mode == "duplicate":
                        self.mode = None
                        output.sendto(packet, ("127.0.0.1", destination))
                        self.altered.set()
                    elif self.mode == "reorder":
                        if self.held is None:
                            self.held = packet
                            self.altered.set()
                            continue
                        output.sendto(packet, ("127.0.0.1", destination))
                        packet, self.held = self.held, None
                        self.mode = None
                output.sendto(packet, ("127.0.0.1", destination))

    def healthy(self):
        for index, process in enumerate(self.processes):
            if process.poll() is not None:
                name = ("server", "client")[index]
                log = (self.path / f"{name}.log").read_text(errors="replace")
                raise AssertionError(f"{name} exited {process.returncode}: {log.replace(self.key, '[redacted]')}")

    def ready(self):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            self.healthy()
            self.app.send(b"ready")
            try:
                if self.app.recv(65535) == b"ready":
                    return
            except (TimeoutError, ConnectionResetError):
                pass
        raise AssertionError("protocol did not reach a working UDP echo")

    def receive(self, timeout=2):
        self.app.settimeout(timeout)
        return self.app.recv(65535)

    def close(self):
        self.stop.set()
        if self.thread:
            self.thread.join(1)
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
        for file in self.files:
            file.close()
        for sock in self.sockets:
            sock.close()
        self.directory.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class ProtocolTests(unittest.TestCase):
    def test_legacy_faketcp_ports_have_exclusive_owners(self):
        with Tunnel() as tunnel:
            tunnel.ready()
            with tunnel.wire_lock:
                syn = next(p for p in tunnel.wire if p["side"] == "client" and p["flags"] & 0x12 == 2)
            for endpoint in (("127.0.0.1", tunnel.server_raw), (syn["source_ip"], syn["source_port"])):
                with self.subTest(endpoint=endpoint), socket.socket(socket.AF_INET, socket.SOCK_STREAM) as rival:
                    rival.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    with self.assertRaises(OSError) as refused:
                        rival.bind(endpoint)
                    self.assertIn(refused.exception.winerror, (10013, 10048))
            tunnel.app.send(b"after-port-contention")
            self.assertEqual(tunnel.receive(), b"after-port-contention")

    def test_existing_http_handshake_sequence_profile(self):
        with Tunnel() as tunnel:
            tunnel.ready()
            with tunnel.wire_lock:
                wire = list(tunnel.wire)
            syn = next(p for p in wire if p["side"] == "client" and p["flags"] & 0x12 == 2)
            syn_ack = next(p for p in wire if p["side"] == "server" and p["flags"] & 0x12 == 0x12)
            self.assertEqual(syn["payload_bytes"], 0)
            self.assertEqual(syn_ack["ack"], (syn["seq"] + 1) & 0xffffffff)
            profiles = {}
            for side in ("client", "server"):
                packets = [p for p in wire if p["side"] == side and p["payload_bytes"]]
                index = next(i for i, p in enumerate(packets) if p["http"])
                http, bare = packets[index:index + 2]
                self.assertFalse(bare["http"])
                self.assertEqual(http["flags"] & 0x1a, 0x18)
                self.assertEqual(bare["flags"] & 0x12, 0x10)
                # This overlap is intentional baseline compatibility, NOT a
                # claim that these packets form a standard TCP byte stream.
                self.assertEqual(http["seq"], bare["seq"])
                self.assertEqual(http["ack"], bare["ack"])
                self.assertNotEqual(http["payload_bytes"], bare["payload_bytes"])
                profiles[side] = dict(http_flags=http["flags"], bare_flags=bare["flags"],
                    http_bytes=http["payload_bytes"], bare_bytes=bare["payload_bytes"],
                    sequence_delta=0, ack_delta=0,
                    observed_gap_ms=round((bare["at"] - http["at"]) * 1000, 3))
            HTTP_SEQUENCE_PROFILE.update(profiles)

    def test_udp_stun_shape_keeps_datagram_semantics(self):
        with Tunnel(http=False, raw_mode="udp", udp_shape=True) as tunnel:
            tunnel.ready()
            self.assertTrue(tunnel.stun_seen)
            for size in (0, 1, 31, 512, 1200, 1300):
                payload = secrets.token_bytes(size)
                tunnel.app.send(payload)
                self.assertEqual(tunnel.receive(), payload)
            tunnel.mode = "drop"
            tunnel.app.send(b"A" * 1200)
            self.assertTrue(tunnel.altered.wait(1))
            tunnel.app.send(b"B" * 1200)
            self.assertEqual(tunnel.receive(), b"B" * 1200)

    def test_udp_mode_boundaries_and_loss(self):
        with Tunnel(http=False, raw_mode="udp") as tunnel:
            tunnel.ready()
            for size in (0, 1, 31, 512, 1200, 1300):
                message = secrets.token_bytes(size)
                tunnel.app.send(message)
                self.assertEqual(tunnel.receive(), message)
            tunnel.mode = "drop"
            tunnel.app.send(b"A" * 1200)
            self.assertTrue(tunnel.altered.wait(1))
            tunnel.app.send(b"B" * 1200)
            self.assertEqual(tunnel.receive(), b"B" * 1200)

    def test_http_and_plain_datagram_boundaries(self):
        for http in (False, True):
            with self.subTest(http=http), Tunnel(http=http) as tunnel:
                tunnel.ready()
                for size in (0, 1, 31, 1200, 1300, 1500):
                    message = secrets.token_bytes(size)
                    tunnel.app.send(message)
                    self.assertEqual(tunnel.receive(), message)
                self.assertEqual(tunnel.http_seen, http)

    def test_dropped_packet_does_not_block_later_packet(self):
        with Tunnel() as tunnel:
            tunnel.ready()
            tunnel.mode = "drop"
            tunnel.app.send(b"A" * 1200)
            self.assertTrue(tunnel.altered.wait(1))
            tunnel.app.send(b"B" * 1200)
            self.assertEqual(tunnel.receive(), b"B" * 1200)
            with self.assertRaises(TimeoutError):
                tunnel.receive(0.25)

    def test_reordered_packets_are_delivered_without_tcp_reassembly(self):
        with Tunnel() as tunnel:
            tunnel.ready()
            tunnel.mode = "reorder"
            tunnel.app.send(b"A" * 1200)
            self.assertTrue(tunnel.altered.wait(1))
            tunnel.app.send(b"B" * 1200)
            self.assertEqual(tunnel.receive(), b"B" * 1200)
            self.assertEqual(tunnel.receive(), b"A" * 1200)

    def test_duplicate_is_rejected_by_anti_replay(self):
        with Tunnel() as tunnel:
            tunnel.ready()
            tunnel.mode = "duplicate"
            tunnel.app.send(b"A" * 1200)
            self.assertEqual(tunnel.receive(), b"A" * 1200)
            self.assertTrue(tunnel.altered.is_set())
            with self.assertRaises(TimeoutError):
                tunnel.receive(0.25)

    def test_ciphertext_tamper_with_valid_tcp_checksum_is_rejected(self):
        with Tunnel() as tunnel:
            tunnel.ready()
            tunnel.mode = "corrupt"
            tunnel.app.send(b"A" * 1200)
            self.assertTrue(tunnel.altered.wait(1))
            tunnel.app.send(b"B" * 1200)
            self.assertEqual(tunnel.receive(), b"B" * 1200)
            with self.assertRaises(TimeoutError):
                tunnel.receive(0.25)

    def test_wrong_secret_cannot_exchange_payload(self):
        with Tunnel(wrong_key=True) as tunnel:
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                tunnel.healthy()
                tunnel.app.send(b"not-authorized")
                with self.assertRaises((TimeoutError, ConnectionResetError)):
                    tunnel.receive(0.1)

    def test_malformed_ip_does_not_terminate_server(self):
        with Tunnel() as tunnel:
            tunnel.ready()
            for packet in (b"\x45", b"\x4f" + bytes(19), b"\x41" + bytes(59), bytes(60)):
                tunnel.proxy_s.sendto(packet, ("127.0.0.1", tunnel.server_wire))
            time.sleep(0.1)
            tunnel.healthy()
            tunnel.app.send(b"after-malformed")
            self.assertEqual(tunnel.receive(), b"after-malformed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--executable", type=Path, default=EXE)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/protocol-results.json")
    args = parser.parse_args()
    EXE = args.executable.resolve()
    start = time.monotonic()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ProtocolTests))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"test_kind": "loopback protocol, no driver, no WAN", "tests": result.testsRun,
        "failures": len(result.failures), "errors": len(result.errors), "elapsed_seconds": time.monotonic() - start,
        "passed": result.wasSuccessful(), "http_handshake_profile": HTTP_SEQUENCE_PROFILE}, indent=2), encoding="utf-8")
    raise SystemExit(0 if result.wasSuccessful() else 1)
