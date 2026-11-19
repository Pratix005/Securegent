"""
Securegent dashboard: a local web page showing the live audit log, pending approvals
and the kill switch. Standard library only.

Security model (it can approve actions, so it is a target):
  * listens on 127.0.0.1 only
  * every /api call needs a random token, sent in the X-Securegent-Token header
    (a custom header also forces a CORS preflight, which we never answer, so other
    websites can't call the API from your browser)
  * the Host header must be localhost/127.0.0.1 (blocks DNS-rebinding attacks)
  * strict Content-Security-Policy with a per-response nonce; the page renders all
    data with textContent, never as HTML (audit entries contain attacker-controlled text)
"""

import hmac
import json
import secrets
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .. import approvals
from ..guard import AuditLog

PAGE = (Path(__file__).parent / "index.html").read_text(encoding="utf-8")
FONT_DIR = Path(__file__).parent / "static" / "fonts"
# Fonts are bundled (SIL Open Font License) so the dashboard never calls out to a CDN.
FONTS = {f.name: f.read_bytes() for f in FONT_DIR.glob("*.woff2")}
MAX_BODY = 10_000


class DashboardState:
    def __init__(self, state_dir: Path, audit_path: Path, kill_switch: Path):
        self.state_dir = state_dir
        self.audit = AuditLog(audit_path)
        self.kill_switch = kill_switch

    def snapshot(self, limit: int) -> dict:
        entries = self.audit.read()
        allowed = sum(e.get("decision") == "allow" for e in entries)
        agents: dict[str, dict] = {}
        for e in entries:
            a = agents.setdefault(str(e.get("agent") or "unidentified"),
                                  {"allowed": 0, "blocked": 0, "last": None})
            a["allowed" if e.get("decision") == "allow" else "blocked"] += 1
            a["last"] = e.get("ts")
        return {
            "events": entries[-limit:][::-1],          # newest first
            "stats": {"total": len(entries), "allowed": allowed, "blocked": len(entries) - allowed},
            "agents": [{"name": k, **v} for k, v in sorted(agents.items(), key=lambda kv: kv[1]["last"] or "",
                                                           reverse=True)],
            "pending": approvals.list_pending(self.state_dir),
            "kill_switch": self.kill_switch.exists(),
            "audit_path": str(self.audit.path),
        }

    def set_kill_switch(self, on: bool) -> None:
        if on:
            self.kill_switch.parent.mkdir(parents=True, exist_ok=True)
            self.kill_switch.write_text("Kill switch turned on from the Securegent dashboard\n",
                                        encoding="utf-8")
        else:
            self.kill_switch.unlink(missing_ok=True)


def make_handler(state: DashboardState, token: str, port: int):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    allowed_origins = {f"http://{h}" for h in allowed_hosts}

    class Handler(BaseHTTPRequestHandler):
        server_version = "Securegent"
        sys_version = ""

        def log_message(self, fmt, *args):     # keep the terminal quiet
            pass

        # --- helpers ---------------------------------------------------------------
        def _send(self, status: int, body: bytes, content_type: str, extra: dict | None = None):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            if "Cache-Control" not in (extra or {}):
                self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, data) -> None:
            self._send(status, json.dumps(data, default=str).encode(), "application/json")

        def _host_ok(self) -> bool:
            return self.headers.get("Host", "") in allowed_hosts

        def _api_ok(self) -> bool:
            if not self._host_ok():
                self._json(HTTPStatus.FORBIDDEN, {"error": "bad host"})
                return False
            sent = self.headers.get("X-Securegent-Token", "")
            if not hmac.compare_digest(sent.encode(), token.encode()):
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "missing or wrong token"})
                return False
            origin = self.headers.get("Origin")
            if origin is not None and origin not in allowed_origins:
                self._json(HTTPStatus.FORBIDDEN, {"error": "bad origin"})
                return False
            return True

        def _body(self) -> dict | None:
            if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
                self._json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "send application/json"})
                return None
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if not 0 < length <= MAX_BODY:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "bad body size"})
                return None
            try:
                data = json.loads(self.rfile.read(length))
            except json.JSONDecodeError:
                data = None
            if not isinstance(data, dict):
                self._json(HTTPStatus.BAD_REQUEST, {"error": "body must be a JSON object"})
                return None
            return data

        # --- routes ----------------------------------------------------------------
        def do_GET(self):
            url = urlparse(self.path)
            if url.path == "/":
                if not self._host_ok():
                    self._send(HTTPStatus.FORBIDDEN, b"bad host", "text/plain")
                    return
                nonce = secrets.token_urlsafe(16)
                csp = (f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
                       "connect-src 'self'; font-src 'self'; img-src 'self' data:; base-uri 'none'; "
                       "form-action 'none'; frame-ancestors 'none'")
                body = PAGE.replace("{{NONCE}}", nonce).encode()
                self._send(HTTPStatus.OK, body, "text/html; charset=utf-8", {"Content-Security-Policy": csp})
            elif url.path.startswith("/static/fonts/"):
                name = url.path.rsplit("/", 1)[-1]
                if not self._host_ok() or name not in FONTS:      # fixed list: no path tricks
                    self._send(HTTPStatus.NOT_FOUND, b"not found", "text/plain")
                    return
                self._send(HTTPStatus.OK, FONTS[name], "font/woff2",
                           {"Cache-Control": "public, max-age=604800, immutable"})
            elif url.path == "/api/state":
                if not self._api_ok():
                    return
                try:
                    limit = max(1, min(1000, int(parse_qs(url.query).get("limit", ["200"])[0])))
                except ValueError:
                    limit = 200
                self._json(HTTPStatus.OK, state.snapshot(limit))
            else:
                self._send(HTTPStatus.NOT_FOUND, b"not found", "text/plain")

        def do_POST(self):
            path = urlparse(self.path).path
            if path not in ("/api/decide", "/api/kill-switch"):
                self._send(HTTPStatus.NOT_FOUND, b"not found", "text/plain")
                return
            if not self._api_ok():
                return
            data = self._body()
            if data is None:
                return
            if path == "/api/decide":
                if not isinstance(data.get("id"), str) or not isinstance(data.get("approved"), bool):
                    self._json(HTTPStatus.BAD_REQUEST, {"error": "need id (string) and approved (bool)"})
                    return
                ok = approvals.decide(data["id"], data["approved"], state.state_dir)
                self._json(HTTPStatus.OK if ok else HTTPStatus.GONE,
                           {"ok": ok} if ok else {"error": "request expired or already answered"})
            else:
                if not isinstance(data.get("on"), bool):
                    self._json(HTTPStatus.BAD_REQUEST, {"error": "need on (bool)"})
                    return
                state.set_kill_switch(data["on"])
                self._json(HTTPStatus.OK, {"kill_switch": state.kill_switch.exists()})

    return Handler


def create_server(state: DashboardState, port: int, token: str | None = None):
    token = token or secrets.token_urlsafe(24)
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(state, token, port))
    server.daemon_threads = True
    return server, token
