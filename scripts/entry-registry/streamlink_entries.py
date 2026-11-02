"""Tagged StreamLink subscriptions on the existing Lucky registry paths.

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
MAX_ENTRIES = 8


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


def normalize_report(value, legacy=False):
    if not isinstance(value, str) or len(value) > 3072:
        raise ValueError("invalid addresses")
    addresses = []
    for line in value.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.lower().startswith("streamlink="):
            line = line[11:].strip()
        elif not legacy:
            raise ValueError("streamlink= required")
        if not line:
            raise ValueError("empty entry")
        for part in re.split(r"[,;\s]+", line):
            address = normalize(part)
            if address not in addresses:
                addresses.append(address)
    if not 1 <= len(addresses) <= MAX_ENTRIES:
        raise ValueError("1-8 addresses required")
    return "\n".join(addresses)


def token_equal(supplied, expected):
    return isinstance(expected, str) and len(expected) >= 32 and hmac.compare_digest(supplied.encode(), expected.encode())


def handle(handler):
    parsed = urlsplit(handler.path)
    path = parsed.path.rstrip("/")
    legacy = path.startswith("/streamlink/")
    shared = path in ("/connector/a", "/connector/b", "/api/v1/report/a", "/api/v1/report/b")
    if not legacy and not shared:
        return False
    if path == "/streamlink/health" and handler.command == "GET":
        handler.send_json(200, {"ok": True, "service": "streamlink-entry-registry"})
        return True
    if legacy and path not in ("/streamlink/connector/akane", "/streamlink/report/akane"):
        handler.send_json(404, {"ok": False, "error": "not found"})
        return True
    write = "/report/" in path
    try:
        secrets = json.loads(CONFIG.read_text())
        if not isinstance(secrets, dict):
            raise ValueError("invalid configuration")
        expected = secrets["write_token" if write else "read_token"]
    except (OSError, ValueError, KeyError):
        if shared:
            return False  # A StreamLink outage must not block EasyTier discovery.
        handler.send_json(503, {"ok": False, "error": "registry not configured"})
        return True
    try:
        query = parse_qs(parsed.query, max_num_fields=8, keep_blank_values=True)
    except ValueError:
        handler.send_json(400, {"ok": False, "error": "invalid query"})
        return True
    supplied = handler.bearer() if write else query.get("token", [""])[0]
    if shared and (path.rsplit("/", 1)[1] != secrets.get("node", "b") or not token_equal(supplied, expected)):
        return False  # Existing tokens continue into the original handler unchanged.
    handler.close_connection = True
    handler.connection.settimeout(5)
    if handler.command != ("POST" if write else "GET"):
        handler.send_json(405, {"ok": False, "error": "method not allowed"})
        return True
    if not token_equal(supplied, expected):
        handler.send_json(403, {"ok": False, "error": "invalid entry token"})
        return True
    try:
        with closing(sqlite3.connect(DATABASE, timeout=3)) as db:
            db.execute("CREATE TABLE IF NOT EXISTS entries (name TEXT PRIMARY KEY, address TEXT NOT NULL, updated INTEGER NOT NULL)")
            if write:
                if handler.headers.get("Transfer-Encoding"):
                    raise ValueError("Content-Length required")
                length = int(handler.headers.get("Content-Length", "0"))
                if not 1 <= length <= 4096:
                    raise ValueError("body must be 1-4096 bytes")
                payload = json.loads(handler.rfile.read(length))
                if not isinstance(payload, dict) or set(payload) != {"address"}:
                    raise ValueError("only address is accepted")
                address = normalize_report(payload["address"], legacy=legacy)
                names = query.get("entry", ["akane"])
                if len(names) != 1 or not re.fullmatch(r"[a-zA-Z0-9_-]{1,32}", names[0]):
                    raise ValueError("invalid entry name")
                name, now = names[0], int(time.time())
                db.execute("BEGIN IMMEDIATE")
                others = db.execute("SELECT address FROM entries WHERE name != ? AND updated >= ?", (name, now-MAX_AGE)).fetchall()
                all_addresses = set(address.splitlines())
                for row in others:
                    all_addresses.update(row[0].splitlines())
                if len(others) >= MAX_ENTRIES or len(all_addresses) > MAX_ENTRIES:
                    raise ValueError("too many active entries")
                db.execute("DELETE FROM entries WHERE updated < ?", (now-MAX_AGE,))
                db.execute("INSERT INTO entries VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET address=excluded.address, updated=excluded.updated", (name, address, now))
                db.commit()
                handler.send_json(200, {"ok": True, "entry": name, "address": address})
            else:
                rows = db.execute("SELECT address, updated FROM entries ORDER BY name").fetchall()
                fresh = [row for row in rows if time.time()-row[1] <= MAX_AGE]
                if not rows:
                    handler.send_json(404, {"ok": False, "error": "awaiting Lucky report"})
                elif not fresh:
                    handler.send_json(503, {"ok": False, "error": "entry report expired"})
                else:
                    addresses = list(dict.fromkeys(address for row in fresh for address in row[0].splitlines()))
                    if len(addresses) > MAX_ENTRIES:
                        raise ValueError("too many entries")
                    # Keep former /streamlink consumers working during migration.
                    handler.send_text(200, "\n".join(("" if legacy else "streamlink=")+value for value in addresses)+"\n")
    except (ValueError, UnicodeError, TimeoutError):
        handler.send_json(400, {"ok": False, "error": "invalid entry report"})
    except (sqlite3.Error, OSError):
        handler.send_json(503, {"ok": False, "error": "registry temporarily unavailable"})
    return True
