"""Incident dashboard. Standard library only.

    cd recall && python3 app.py            # dashboard at http://127.0.0.1:8000
    cd recall && python3 app.py --live     # also serve secure links to phones on the same Wi-Fi

In --live mode the server listens on the network, but only the /l/ link pages answer other
devices; the dashboard and its API stay reachable from this machine only. Set RECALL_PUBLIC_URL
(for example a tunnel URL) to change the address printed in links and the QR code.
"""

import json
import os
import re
import secrets
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from recall import phone, qr, replay  # noqa: E402
from recall.incidents import ApprovalError, IncidentStore  # noqa: E402
from recall.live import LiveSession  # noqa: E402
from recall.scenario import load_dir  # noqa: E402
from recall.timeutil import iso  # noqa: E402

STATIC = Path(__file__).resolve().parent / "static"
SCENARIOS = {s["id"]: s for d in ("seeded", "holdout") for s in load_dir(d)}
STORE = IncidentStore(llm=None)
LIVE = LiveSession(STORE)
CONFIG = {"bind": "127.0.0.1", "port": 8000}

LINK_RE = re.compile(r"^/l/(lk_[0-9a-f]{10})(/status)?/?$")
MSG_RE = re.compile(r"^/m/(msg_[0-9a-f]{10})(/status|/try)?/?$")
LOCAL = {"127.0.0.1", "::1", "::ffff:127.0.0.1"}


def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))  # no packet is sent; this only picks the outbound interface
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def public_base():
    if os.environ.get("RECALL_PUBLIC_URL"):
        return os.environ["RECALL_PUBLIC_URL"].rstrip("/"), True
    if CONFIG["bind"] == "0.0.0.0":
        ip = lan_ip()
        if ip:
            return f"http://{ip}:{CONFIG['port']}", True
    return f"http://127.0.0.1:{CONFIG['port']}", False


def _public(result):
    def clean_ev(i):
        return {k: v for k, v in i.items() if k not in ("entries", "access", "window")}
    return {
        "incident_id": result["incident_id"], "action_id": result["action_id"], "verdict": result["verdict"],
        "reasons": result["reasons"], "facts": result["facts"], "drafts": result["drafts"],
        "evidence": [clean_ev(i) for i in result["evidence"]],
        "reversals": result["facts"]["reversals"],
        "drafts_pending": result.get("drafts_pending", False),
    }


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json", headers=None):
        data = body if isinstance(body, bytes) else json.dumps(body, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def _local(self):
        """Dashboard access: a loopback client that asked for a loopback host directly. A tunnel
        (ngrok and the like) also connects from loopback, but it forwards a public Host or adds
        X-Forwarded-For, so it only ever gets the link pages."""
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
        forwarded = any(self.headers.get(h) for h in ("X-Forwarded-For", "X-Forwarded-Host", "Forwarded"))
        return self.client_address[0] in LOCAL and host in ("127.0.0.1", "localhost", "::1") and not forwarded

    def log_message(self, fmt, *args):
        pass

    def _visitor(self):
        """A per-device cookie so each phone gets one stable guest label."""
        cookie = self.headers.get("Cookie", "")
        token = next((c.split("=", 1)[1] for c in cookie.split("; ") if c.startswith("rv=")), None)
        if token and re.fullmatch(r"[0-9a-f]{16}", token):
            return token, {}
        token = secrets.token_hex(8)
        return token, {"Set-Cookie": f"rv={token}; Path=/; Max-Age=86400; SameSite=Lax; HttpOnly"}

    def _link(self, m):
        link_id, status = m.group(1), m.group(2)
        if status:
            return self._send(200, LIVE.link_status(link_id))
        token, headers = self._visitor()
        state, doc = LIVE.open_link(link_id, token, self.headers.get("User-Agent", ""))
        html = "text/html; charset=utf-8"
        if state == "unknown":
            return self._send(404, phone.unknown_page(), html, headers)
        if state == "revoked":
            return self._send(410, phone.revoked_page(doc["revoked_at"], LIVE.visitor(token, "")), html, headers)
        return self._send(200, phone.document_page(link_id, doc), html, headers)

    def _message(self, m, method):
        message_id, sub = m.group(1), m.group(2)
        token, headers = self._visitor()
        ua = self.headers.get("User-Agent", "")
        if sub == "/status" and method == "GET":
            return self._send(200, LIVE.key_status(message_id))
        if sub == "/try" and method == "POST":
            r = LIVE.try_key(message_id, token, ua)
            return self._send(200 if r else 404, r or {"error": "unknown"}, headers=headers)
        if sub is None and method == "GET":
            state, data = LIVE.open_message(message_id, token, ua)
            if state == "unknown":
                return self._send(404, phone.unknown_page(), "text/html; charset=utf-8", headers)
            return self._send(200, phone.message_page(message_id, data), "text/html; charset=utf-8", headers)
        return self._send(405, {"error": "method not allowed"})

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        m = LINK_RE.match(path)
        if m:
            return self._link(m)
        m = MSG_RE.match(path)
        if m:
            return self._message(m, "GET")
        if not self._local():
            return self._send(403, b"Recall: only secure links are served to other devices.", "text/plain")
        if path in ("/", "/index.html"):
            return self._send(200, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
        if path == "/api/scenarios":
            return self._send(200, [{"id": s["id"], "title": s["title"], "expected": s["expected"],
                                     "set": "holdout" if s["id"].startswith("h") else "seeded",
                                     "demo": s.get("demo")} for s in SCENARIOS.values()])
        if path == "/api/incidents":
            return self._send(200, [_public(r.result) | {"scenario": r.spec["id"], "title": r.spec["title"],
                                                         "expected": r.spec["expected"]}
                                    for r in STORE.runs.values()][::-1])
        if path == "/api/live":
            base, reachable = public_base()
            state = LIVE.state()
            if state.get("path"):
                state["url"] = base + state["path"]
            return self._send(200, state | {"reachable": reachable, "base": base})
        if path == "/api/live/qr.svg":
            state = LIVE.state()
            if not state.get("path"):
                return self._send(404, {"error": "nothing sent yet"})
            return self._send(200, qr.svg(public_base()[0] + state["path"]).encode(), "image/svg+xml")
        if path.startswith("/api/replay/"):
            run = STORE.runs.get(path.rsplit("/", 1)[1])
            if not run:
                return self._send(404, {"error": "unknown incident"})
            return self._send(200, replay.build(run))
        if path.startswith("/api/ledger/"):
            run = STORE.runs.get(path.rsplit("/", 1)[1])
            if not run:
                return self._send(404, {"error": "unknown incident"})
            return self._send(200, {"verified": run.ledger.verify(),
                                    "entries": [e | {"at": iso(e["ts"])} for e in run.ledger.entries()]})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        m = MSG_RE.match(self.path.split("?", 1)[0])
        if m:
            return self._message(m, "POST")
        if not self._local():
            return self._send(403, b"Recall: the dashboard only accepts requests from this machine.", "text/plain")
        body = self._body()
        try:
            if self.path == "/api/run":
                spec = SCENARIOS[body["scenario"]]
                return self._send(200, _public(STORE.run(spec)))
            if self.path == "/api/approve":
                d = STORE.approve(body["incident_id"], body["kind"], body.get("approver", "").strip(), body.get("text"))
                return self._send(200, d)
            if self.path == "/api/reject":
                d = STORE.reject(body["incident_id"], body["kind"], body.get("approver", "").strip(), body.get("reason", ""))
                return self._send(200, d)
            if self.path == "/api/live/send":
                return self._send(200, LIVE.send(public_base()[0], body.get("mode", "link"), body.get("outage", False)))
            if self.path == "/api/live/outage":
                return self._send(200, LIVE.set_outage(body.get("on", False)))
            if self.path == "/api/live/recall":
                return self._send(200, LIVE.recall())
            if self.path == "/api/incidents/clear":
                STORE.clear()
                return self._send(200, {"cleared": True})
            if self.path == "/api/live/reset":
                LIVE.reset()
                return self._send(200, {"status": "idle"})
        except ApprovalError as e:
            return self._send(422, {"error": str(e)})
        except (RuntimeError, ValueError) as e:
            return self._send(409, {"error": str(e)})
        except KeyError as e:
            return self._send(404, {"error": f"unknown: {e}"})
        self._send(404, {"error": "not found"})


def main():
    CONFIG["port"] = int(os.environ.get("PORT", "8000"))
    CONFIG["bind"] = "0.0.0.0" if "--live" in sys.argv else "127.0.0.1"
    server = ThreadingHTTPServer((CONFIG["bind"], CONFIG["port"]), Handler)
    llm = "on" if os.environ.get("ANTHROPIC_API_KEY") else "off (template drafts)"
    print(f"Recall dashboard at http://127.0.0.1:{CONFIG['port']}   LLM drafting: {llm}")
    base, reachable = public_base()
    if reachable:
        print(f"Live demo links served at {base}/l/...  (dashboard stays local to this machine)")
    else:
        print("Live demo: run with --live to let phones on the same Wi-Fi open the links")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
