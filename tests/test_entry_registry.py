import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from contextlib import closing

spec = importlib.util.spec_from_file_location("entries", Path(__file__).resolve().parents[1] / "scripts/entry-registry/streamlink_entries.py")
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
            for address in ("127.0.0.1:80", "10.0.0.1:44680", "8.8.8.8:0", "https://example.com/", "8.8.8.8:44680\n1.1.1.1:10"):
                report.rfile = io.BytesIO(json.dumps({"address": address}).encode()); report.headers["Content-Length"] = str(len(report.rfile.getvalue()))
                entries.handle(report); self.assertEqual(report.result[0], 400)
            with closing(sqlite3.connect(entries.DATABASE)) as db:
                db.execute("UPDATE entries SET updated=0")
                db.commit()
            entries.handle(read); self.assertEqual(read.result[0], 503)


if __name__ == "__main__": unittest.main()
