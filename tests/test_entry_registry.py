import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from contextlib import closing

spec = importlib.util.spec_from_file_location("entries", Path(__file__).resolve().parents[1] / "scripts/entry-registry/conwu_entries.py")
entries = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entries)


class Handler:
    def __init__(self, path, method="GET", body=b"", token=""):
        self.path, self.command, self.rfile, self.token = path, method, io.BytesIO(body), token
        self.headers = {"Content-Length": str(len(body))}
        self.connection = self
        self.result = None
    def settimeout(self, _): pass
    def bearer(self): return self.token
    def send_json(self, code, data): self.result = (code, data)
    def send_text(self, code, data): self.result = (code, data)


class Tests(unittest.TestCase):
    def test_shared_routes_and_independent_reports(self):
        with tempfile.TemporaryDirectory() as folder:
            entries.CONFIG = Path(folder) / "config.json"
            entries.DATABASE = Path(folder) / "entries.db"
            entries.CONFIG.write_text(json.dumps({"read_token": "r"*40, "write_token": "w"*40}))
            def request(body=None, name=None, token=None, path=None):
                write = body is not None
                path = path or ("/api/v1/report/b" if write else "/connector/b?token="+"r"*40)
                if name is not None:
                    path += "?entry="+name
                handler = Handler(path, "POST" if write else "GET", json.dumps(body).encode() if write else b"", token if token is not None else "w"*40)
                handled = entries.handle(handler)
                return handled, handler.result
            for path, token in (("/api/v1/report/b", "old-easytier-token"),("/api/v1/report/b", "r"*40),("/api/v1/report/a", "w"*40)):
                self.assertEqual(request({"address":"streamlink=8.8.8.8:40000"}, token=token, path=path), (False, None))
            self.assertEqual(request()[1][0], 404)
            self.assertEqual(request({"address":"8.8.8.8:40000"})[1][0], 400)
            self.assertEqual(request({"address":"streamlink=8.8.8.8:40000"})[1][0], 200)
            self.assertEqual(request({"address":"streamlink=1.1.1.1:41000"}, "fiber")[1][0], 200)
            self.assertEqual(request()[1], (200, "streamlink=8.8.8.8:40000\nstreamlink=1.1.1.1:41000\n"))
            self.assertEqual(request({"address":"streamlink=8.8.8.8:40001"})[1][0], 200)
            self.assertEqual(request()[1], (200, "streamlink=8.8.8.8:40001\nstreamlink=1.1.1.1:41000\n"))
            good = request()[1]
            for value in ("streamlink=", "streamlink=127.0.0.1:80", "streamlink=https://example.com/", "streamlink=8.8.8.8:1\neasyTier=1.1.1.1:2"):
                self.assertEqual(request({"address":value})[1][0], 400)
                self.assertEqual(request()[1], good)
            for name in ("bad/name", "", "x"*33, "a&entry=b"):
                self.assertEqual(request({"address":"streamlink=8.8.8.8:5"}, name)[1][0], 400)
            # Updating one rule cannot overwrite another rule or exceed the aggregate bound.
            seven = "streamlink="+",".join("8.8.4.4:"+str(1000+i) for i in range(7))
            self.assertEqual(request({"address":seven})[1][0], 200)
            self.assertEqual(request({"address":"streamlink=9.9.9.9:9000"}, "extra")[1][0], 400)
            with closing(sqlite3.connect(entries.DATABASE)) as db:
                db.execute("UPDATE entries SET updated=0 WHERE name='fiber'"); db.commit()
            self.assertEqual(request({"address":"streamlink=9.9.9.9:9000"}, "extra")[1][0], 200)
            self.assertEqual(len(request()[1][1].splitlines()), 8)
            # A missing StreamLink config must leave the legacy HTTP handler available.
            entries.CONFIG.unlink()
            self.assertEqual(request(), (False, None))

    def test_routes(self):
        with tempfile.TemporaryDirectory() as folder:
            entries.CONFIG = Path(folder) / "config.json"
            entries.DATABASE = Path(folder) / "entries.db"
            entries.CONFIG.write_text(json.dumps({"read_token": "r"*40, "write_token": "w"*40}))
            old = Handler("/connector/b?token=old")
            self.assertFalse(entries.handle(old))
            self.assertIsNone(old.result)
            self.assertFalse(entries.DATABASE.exists())
            read_path = "/streamlink/connector/akane?token="+"r"*40
            missing = Handler(read_path); entries.handle(missing)
            self.assertEqual(missing.result[0], 404)
            for token in ("", "r"*40, "old-easytier-token"):
                denied = Handler("/streamlink/report/akane", "POST", b'{"address":"8.8.8.8:40000"}', token)
                entries.handle(denied); self.assertEqual(denied.result[0], 403)
            report = Handler("/streamlink/report/akane", "POST", b'{"address":"tcp://8.8.8.8:40000"}', "w"*40)
            entries.handle(report); self.assertEqual(report.result[0], 200)
            read = Handler(read_path); entries.handle(read)
            self.assertEqual(read.result, (200, "8.8.8.8:40000\n"))
            for address in ("127.0.0.1:80", "10.0.0.1:44680", "8.8.8.8:0", "https://example.com/"):
                report.rfile = io.BytesIO(json.dumps({"address": address}).encode()); report.headers["Content-Length"] = str(len(report.rfile.getvalue()))
                entries.handle(report); self.assertEqual(report.result[0], 400)
            with closing(sqlite3.connect(entries.DATABASE)) as db:
                db.execute("UPDATE entries SET updated=0")
                db.commit()
            entries.handle(read); self.assertEqual(read.result[0], 503)


if __name__ == "__main__": unittest.main()
