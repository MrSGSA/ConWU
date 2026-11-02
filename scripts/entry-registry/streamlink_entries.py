"""Isolated StreamLink entry routes for the existing Lucky address registry.

Only address metadata is served. No pairing credentials or traffic relay.
The caller's Handler supplies send_json/send_text/bearer; existing routes stay intact.
"""
import hmac
from contextlib import closing
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import time
from urllib.parse import parse_qs, urlsplit

CONFIG = Path(os.getenv("STREAMLINK_ENTRY_CONFIG", "/data/streamlink-entry-secrets.json"))
DATABASE = Path(os.getenv("STREAMLINK_ENTRY_DB", "/data/streamlink-entries.db"))
MAX_AGE = 3600


def normalize(value):
    if not isinstance(value, str) or len(value) > 128:
        raise ValueError("address must be IPv4:port")
    match = re.fullmatch(r"(?:tcp://)?([0-9.]+):([0-9]{1,5})", value.strip())
    if not match:
        raise ValueError("address must be IPv4:port")
    ip = ipaddress.IPv4Address(match[1])
    port = int(match[2])
    if not ip.is_global or ip.is_multicast or not 1 <= port <= 65535:
        raise ValueError("public IPv4 and a valid port are required")
    return f"{ip}:{port}"


def handle(handler):
    parsed = urlsplit(handler.path)
    if not parsed.path.startswith("/streamlink/"):
        return False
    handler.close_connection = True
    handler.connection.settimeout(5)
    if parsed.path == "/streamlink/health" and handler.command == "GET":
        handler.send_json(200, {"ok": True, "service": "streamlink-entry-registry"})
        return True
    if parsed.path not in ("/streamlink/connector/akane", "/streamlink/report/akane"):
        handler.send_json(404, {"ok": False, "error": "not found"})
        return True
    write = parsed.path == "/streamlink/report/akane"
    if handler.command != ("POST" if write else "GET"):
        handler.send_json(405, {"ok": False, "error": "method not allowed"})
        return True
    try:
        secrets = json.loads(CONFIG.read_text())
        expected = secrets["write_token" if write else "read_token"]
    except (OSError, ValueError, KeyError):
        handler.send_json(503, {"ok": False, "error": "registry not configured"})
        return True
    try:
        query = parse_qs(parsed.query, max_num_fields=8)
    except ValueError:
        handler.send_json(400, {"ok": False, "error": "invalid query"})
        return True
    supplied = handler.bearer() if write else query.get("token", [""])[0]
    if not isinstance(expected, str) or len(expected) < 32 or not hmac.compare_digest(supplied.encode(), expected.encode()):
        handler.send_json(403, {"ok": False, "error": "invalid entry token"})
        return True
    try:
        with closing(sqlite3.connect(DATABASE, timeout=3)) as db:
            db.execute("CREATE TABLE IF NOT EXISTS entries (name TEXT PRIMARY KEY, address TEXT NOT NULL, updated INTEGER NOT NULL)")
            if write:
                if handler.headers.get("Transfer-Encoding"):
                    raise ValueError("Content-Length required")
                length = int(handler.headers.get("Content-Length", "0"))
                if not 1 <= length <= 512:
                    raise ValueError("body must be 1-512 bytes")
                payload = json.loads(handler.rfile.read(length))
                if not isinstance(payload, dict) or set(payload) != {"address"}:
                    raise ValueError("only address is accepted")
                address = normalize(payload["address"])
                db.execute("INSERT INTO entries VALUES ('akane', ?, ?) ON CONFLICT(name) DO UPDATE SET address=excluded.address, updated=excluded.updated", (address, int(time.time())))
                db.commit()
                handler.send_json(200, {"ok": True, "address": address})
            else:
                row = db.execute("SELECT address, updated FROM entries WHERE name='akane'").fetchone()
                if row is None:
                    handler.send_json(404, {"ok": False, "error": "awaiting Lucky report"})
                elif time.time() - row[1] > MAX_AGE:
                    handler.send_json(503, {"ok": False, "error": "entry report expired"})
                else:
                    handler.send_text(200, row[0] + "\n")
    except (ValueError, UnicodeError, TimeoutError):
        handler.send_json(400, {"ok": False, "error": "invalid entry report"})
    except (sqlite3.Error, OSError):
        handler.send_json(503, {"ok": False, "error": "registry temporarily unavailable"})
    return True
