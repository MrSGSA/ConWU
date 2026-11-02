"""Actual HTTP compatibility test against a supplied legacy registry app.py snapshot.

Usage: python tests/test_entry_registry_http.py path/to/registry-app.py
Uses isolated databases and fixture tokens; never contacts the deployed registry.
"""
import importlib.util
import gc
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"scripts/entry-registry"))
import streamlink_entries as entries

for key in ("A_WRITE_TOKEN", "A_READ_TOKEN", "B_WRITE_TOKEN", "B_READ_TOKEN", "ADMIN_TOKEN"):
    os.environ[key] = "fixture-"+key
spec = importlib.util.spec_from_file_location("registry", sys.argv[1])
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)

with tempfile.TemporaryDirectory() as folder:
    app.DB_PATH = Path(folder)/"legacy.db"
    app.init_db()
    entries.DATABASE = Path(folder)/"streamlink.db"
    entries.CONFIG = Path(folder)/"config.json"
    entries.CONFIG.write_text(json.dumps({"read_token":"r"*40, "write_token":"w"*40}))
    server = app.ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    def request(path, body=None, token=""):
        req = urllib.request.Request("http://127.0.0.1:"+str(server.server_port)+path,
            headers={"Authorization":"Bearer "+token,"Content-Type":"application/json"},
            data=None if body is None else json.dumps(body).encode())
        try:
            response = urllib.request.urlopen(req, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, response.read().decode()
    try:
        assert request("/healthz")[0] == 200
        assert request("/api/v1/report/b", {"address":"1.1.1.1:11010"}, "fixture-B_WRITE_TOKEN")[0] == 200
        before = request("/connector/b?token=fixture-A_READ_TOKEN")
        assert before == (200, "tcp://1.1.1.1:11010\n")
        read = "/connector/b?token="+"r"*40
        assert request(read)[0] == 404
        for token in ("", "r"*40, "fixture-A_READ_TOKEN", "fixture-B_WRITE_TOKEN"):
            assert request("/api/v1/report/b", {"address":"streamlink=8.8.8.8:44680"}, token)[0] >= 400
        assert request("/api/v1/report/a", {"address":"streamlink=8.8.8.8:44680"}, "w"*40)[0] == 403
        assert request("/api/v1/report/b", {"address":"streamlink=8.8.8.8:44680"}, "w"*40)[0] == 200
        assert request("/api/v1/report/b?entry=backup", {"address":"streamlink=9.9.9.9:44681"}, "w"*40)[0] == 200
        assert request(read) == (200, "streamlink=8.8.8.8:44680\nstreamlink=9.9.9.9:44681\n")
        assert request("/connector/b?token=fixture-A_READ_TOKEN") == before
        # Prior Lucky task remains usable while the user changes its URL/body.
        assert request("/streamlink/report/akane", {"address":"8.8.8.8:44682"}, "w"*40)[0] == 200
        assert request(read) == (200, "streamlink=8.8.8.8:44682\nstreamlink=9.9.9.9:44681\n")
        assert request("/streamlink/connector/akane?token="+"r"*40) == (200, "8.8.8.8:44682\n9.9.9.9:44681\n")
        assert request("/api/v1/report/b", {"address":"1.1.1.1:11011"}, "fixture-B_WRITE_TOKEN")[0] == 200
        assert request("/connector/b?token=fixture-A_READ_TOKEN") == (200, "tcp://1.1.1.1:11011\n")
        assert request(read)[1].startswith("streamlink=8.8.8.8:44682")
        print("PASS shared HTTP routes, scoped tokens, independent rule updates, legacy compatibility, unchanged EasyTier writer and reader")
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
        gc.collect()  # The supplied legacy app relies on sqlite connection finalizers.
