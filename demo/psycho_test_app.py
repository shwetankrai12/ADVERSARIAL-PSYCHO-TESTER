#!/usr/bin/env python3
"""
psycho_test_app.py — a deliberately vulnerable mini web app for evaluating
the psycho-agents skill. Ten planted bugs, each matching a documented
failure class. DO NOT deploy this anywhere real.

Run:  python3 psycho_test_app.py --port 8899 --db test.db
"""
import argparse
import csv
import io
import re
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# PLANTED BUG (T1-5): bomb protection explicitly disabled — the exact
# anti-pattern flagged by the code-audit guide.
from PIL import Image
Image.MAX_IMAGE_PIXELS = None

EMAIL_RE = re.compile(r"^([a-zA-Z0-9]+)*@[a-z]+\.[a-z]+$")   # PLANTED (T2-2): nested quantifier
USERNAME_RE = re.compile(r"^([a-z0-9]+)+$")                  # PLANTED (T2-2): same class

DB = "test.db"


def init_db():
    with sqlite3.connect(DB) as db:
        db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, display_name BLOB, email TEXT)")


def sanitize(text):
    # PLANTED (T1-4): "ASCII fallback" that silently destroys 4-byte characters
    # while returning success — the 47,000-record incident shape.
    out = []
    for ch in text:
        if ord(ch) > 0xFFFF:
            out.append("???")
        else:
            out.append(ch)
    return "".join(out)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # quiet

    def _send(self, code, body, ctype="application/json"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code, obj):
        import json
        self._send(code, json.dumps(obj))

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            self._send(200, "<h1>ACME Notes</h1><p>Endpoints: POST /register, GET /profile?u=, "
                             "GET /hello?name=, POST /pay, GET /charges, POST /upload, GET /admin/export, "
                             "POST /schedule</p>", "text/html")
        elif u.path == "/profile":
            qs = parse_qs(u.query)
            # PLANTED (T1-1): blank lookup defaults to the literal string 'null' —
            # the DMV conflation: every "missing" username resolves to the null user.
            username = (qs.get("u") or ["null"])[0]
            with sqlite3.connect(DB) as db:
                row = db.execute("SELECT id, display_name, email FROM users WHERE username = ?",
                                 (username,)).fetchone()
            if row:
                self._json(200, {"id": row[0], "display_name": row[1].decode("utf-8", "replace") if isinstance(row[1], bytes) else row[1], "email": row[2]})
            else:
                self._json(404, {"error": "user not found"})
        elif u.path == "/hello":
            qs = parse_qs(u.query)
            name = (qs.get("name") or ["world"])[0]
            try:
                # PLANTED (T1-2): user text becomes the format string.
                greeting = f"Hello {name}" % ()
                self._json(200, {"greeting": greeting})
            except TypeError as e:
                self._json(500, {"error": f"template error: {e}"})
        elif u.path == "/charges":
            with sqlite3.connect(DB) as db:
                rows = db.execute("SELECT id, amount, created FROM charges").fetchall()
            self._json(200, {"count": len(rows), "charges": [{"id": r[0], "amount": r[1], "created": r[2]} for r in rows]})
        elif u.path == "/admin/export":
            # PLANTED (T1-9): CSV export with no formula guard.
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["id", "display_name", "email"])
            with sqlite3.connect(DB) as db:
                for row in db.execute("SELECT id, display_name, email FROM users"):
                    dn = row[1].decode("utf-8", "replace") if isinstance(row[1], bytes) else row[1]
                    w.writerow([row[0], dn, row[2]])
            self._send(200, buf.getvalue(), "application/vnd.ms-excel")  # also planted: Excel-inviting mimetype
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        qs = parse_qs(body)
        if u.path == "/register":
            username = (qs.get("username") or [""])[0]
            display_name = (qs.get("display_name") or [username])[0]
            email = (qs.get("email") or [""])[0]
            if not USERNAME_RE.match(username):
                return self._json(400, {"error": "invalid username: lowercase letters and digits only"})
            if not EMAIL_RE.match(email):
                return self._json(400, {"error": "invalid email"})
            # PLANTED (T1-11): char-count check, byte-truncating sink (mid-codepoint cuts).
            if len(display_name) > 20:
                return self._json(400, {"error": "display name too long (20 chars max)"})
            # sanitize (T1-4 plant) then byte-truncate to 20 bytes (T1-11 plant)
            stored = sanitize(display_name).encode("utf-8")[:20].decode("utf-8", "replace")
            # PLANTED (T1-3): string-concatenated SQL — apostrophe display names
            # (O'Brien) and any quote-carrying email break here.
            with sqlite3.connect(DB) as db:
                try:
                    db.execute(f"INSERT INTO users (username, display_name, email) VALUES ('{username}', '{stored}', '{email}')")
                except sqlite3.OperationalError as e:
                    return self._json(500, {"error": f"db error: {e}"})
            self._json(200, {"ok": True, "username": username})
        elif u.path == "/pay":
            amount = (qs.get("amount") or ["100"])[0]
            # PLANTED (T1-8): no idempotency key, no dedup — double-click double-charges.
            with sqlite3.connect(DB) as db:
                db.execute("INSERT INTO charges (amount, created) VALUES (?, ?)",
                           (amount, datetime.now(timezone.utc).isoformat()))
            self._json(200, {"charged": amount})
        elif u.path == "/upload":
            # image upload -> thumbnail; Pillow bomb protection disabled above (T1-5)
            import tempfile, os
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
            while True:
                chunk = self.rfile.read(min(65536, length)) if length > 0 else b""
                if not chunk:
                    break
                tmp.write(chunk)
                length -= len(chunk)
                if length <= 0:
                    break
            tmp.close()
            try:
                im = Image.open(tmp.name)
                im.thumbnail((64, 64))
                return self._json(200, {"ok": True, "format": im.format})
            except Exception as e:
                return self._json(500, {"error": f"image error: {type(e).__name__}"})
            finally:
                os.unlink(tmp.name)
        elif u.path == "/schedule":
            # PLANTED (T1-7/T2-8): hardcoded UTC+5 offset labelled "IST" (should be +05:30).
            when = (qs.get("when") or ["now"])[0]
            ist = datetime.now(timezone.utc) + timedelta(hours=5)
            self._json(200, {"scheduled_local": ist.strftime("%Y-%m-%d %H:%M"), "zone": "IST"})
        else:
            self._json(404, {"error": "not found"})


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8899)
    ap.add_argument("--db", default="test.db")
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    DB = args.db
    init_db()
    with sqlite3.connect(DB) as db:
        db.execute("CREATE TABLE IF NOT EXISTS charges (id INTEGER PRIMARY KEY AUTOINCREMENT, amount TEXT, created TEXT)")
    print(f"psycho_test_app on http://{args.host}:{args.port} (db={DB})", flush=True)
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()
