"""
Serve the Securegent MCP proxy over Streamable HTTP, for AI apps that connect to MCP
servers by URL instead of starting a command.

    client  --HTTP-->  http://127.0.0.1:8765/mcp  (this)  --stdio or HTTP-->  real server

Every client session (one `initialize`) gets its own McpProxy, its own upstream
connection and its own token, so taint memory and tool pins never mix between clients.
Replies to POSTs are plain JSON; messages the server starts on its own (notifications,
requests) are delivered on the optional GET event stream.

Security:
  - Binds to 127.0.0.1 by default. Browser requests from other origins are refused
    (protection against DNS rebinding, as the MCP spec asks).
  - If SECUREGENT_LISTEN_TOKEN is set, every request needs "Authorization: Bearer <token>".
    Listening on a non-loopback address is refused without it.
"""

import hmac
import ipaddress
import json
import os
import queue
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable
from urllib.parse import urlparse

from .upstream import _log

MAX_BODY = 10 * 1024 * 1024
REPLY_TIMEOUT = 900            # seconds a POST waits for its replies (approvals can be slow)
TOKEN_ENV = "SECUREGENT_LISTEN_TOKEN"  # nosec B105: not a password: a variable name or message


def _key(request_id) -> str:
    return json.dumps(request_id, sort_keys=True)      # 1 and "1" are different ids


class _QueueReader:
    """Looks like a binary stream of lines to McpProxy; fed from HTTP requests."""

    def __init__(self):
        self.q: "queue.Queue[bytes | None]" = queue.Queue()

    def __iter__(self):
        while True:
            line = self.q.get()
            if line is None:
                return
            yield line


class _Router:
    """Looks like the proxy's client stdout; routes each reply to the POST waiting for it."""

    def __init__(self, session: "_Session"):
        self.session = session

    def write(self, data: bytes) -> None:
        for line in data.splitlines():
            if line.strip():
                try:
                    self.session.deliver(json.loads(line))
                except json.JSONDecodeError:
                    pass

    def flush(self) -> None:
        pass


class _Session:
    def __init__(self, make_proxy: Callable, session_id: str):
        self.id = session_id
        self.reader = _QueueReader()
        self.events: "queue.Queue[dict | None]" = queue.Queue()   # for the GET stream
        self.waiters: dict[str, dict] = {}
        self.lock = threading.Lock()
        self.closed = threading.Event()
        self.has_stream = False
        self.proxy = make_proxy(self.reader, _Router(self))
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self) -> None:
        try:
            self.proxy.run()
        except Exception as e:
            _log(f"session {self.id[:8]} ended with an error: {e}")
        finally:
            self.closed.set()
            self.events.put(None)
            with self.lock:
                waiting = list(self.waiters.values())
            for w in waiting:
                w["reply"] = None
                w["done"].set()

    def expect(self, request_id) -> dict:
        w = {"done": threading.Event(), "reply": None}
        with self.lock:
            self.waiters[_key(request_id)] = w
        return w

    def deliver(self, msg) -> None:
        if isinstance(msg, dict) and "id" in msg and ("result" in msg or "error" in msg):
            with self.lock:
                w = self.waiters.pop(_key(msg["id"]), None)
            if w is not None:
                w["reply"] = msg
                w["done"].set()
                return
        self.events.put(msg)                    # server-initiated, or nobody waiting

    def send(self, msg) -> None:
        self.reader.q.put(json.dumps(msg, separators=(",", ":")).encode())

    def close(self) -> None:
        self.reader.q.put(None)


class HttpListener:
    def __init__(self, make_proxy: Callable, host: str = "127.0.0.1", port: int = 8765,
                 path: str = "/mcp", token: str | None = None):
        """make_proxy(client_in, client_out) -> McpProxy, called once per client session."""
        if not token and not _is_loopback(host):
            raise ValueError(f"listening on {host} needs a token: set {TOKEN_ENV}")
        self.make_proxy, self.path, self.token = make_proxy, path, token
        self.sessions: dict[str, _Session] = {}
        self.lock = threading.Lock()
        self.httpd = ThreadingHTTPServer((host, port), self._handler())
        self.httpd.daemon_threads = True
        h, p = self.httpd.server_address[:2]
        self.url = f"http://{'[' + h + ']' if ':' in h else h}:{p}{path}"

    def serve_forever(self) -> None:
        _log(f"listening on {self.url}")
        try:
            self.httpd.serve_forever()
        finally:
            for s in list(self.sessions.values()):
                s.close()

    def shutdown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        for s in list(self.sessions.values()):
            s.close()

    def _handler(self):
        listener = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            # --- helpers ------------------------------------------------------------
            def _send(self, status: int, body=None, headers: dict | None = None) -> None:
                data = b"" if body is None else json.dumps(body, separators=(",", ":")).encode()
                self.send_response(status)
                if body is not None:
                    self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            def _error(self, status: int, message: str, request_id=None) -> None:
                self._send(status, {"jsonrpc": "2.0", "id": request_id,
                                    "error": {"code": -32600, "message": message}})

            def _checks_pass(self) -> bool:
                if urlparse(self.path).path != listener.path:
                    self._send(404, {"error": "not found"})
                    return False
                origin = self.headers.get("Origin")
                if origin and not _is_loopback(urlparse(origin).hostname or ""):
                    self._send(403, {"error": "origin not allowed"})
                    return False
                if listener.token:
                    given = self.headers.get("Authorization", "")
                    if not hmac.compare_digest(given.encode(), f"Bearer {listener.token}".encode()):
                        self._send(401, {"error": "missing or wrong bearer token"},
                                   {"WWW-Authenticate": "Bearer"})
                        return False
                return True

            def _session(self) -> "_Session | None":
                sid = self.headers.get("Mcp-Session-Id")
                if not sid:
                    self._error(400, "missing Mcp-Session-Id header")
                    return None
                with listener.lock:
                    s = listener.sessions.get(sid)
                if s is None or s.closed.is_set():
                    self._send(404, {"error": "unknown or ended session; initialize again"})
                    return None
                return s

            # --- methods ------------------------------------------------------------
            def do_POST(self):
                if not self._checks_pass():
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    length = -1
                if not 0 < length <= MAX_BODY:
                    self._error(413 if length > MAX_BODY else 400, "bad or missing body")
                    return
                try:
                    body = json.loads(self.rfile.read(length))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    self._error(400, "body is not JSON")
                    return
                messages = body if isinstance(body, list) else [body]
                if not messages or not all(isinstance(m, dict) for m in messages):
                    self._error(400, "expected a JSON-RPC message or batch")
                    return

                headers = {}
                if any(m.get("method") == "initialize" for m in messages):
                    if len(messages) != 1 or "id" not in messages[0]:
                        self._error(400, "initialize must be sent on its own")
                        return
                    sid = uuid.uuid4().hex
                    try:
                        session = _Session(listener.make_proxy, sid)
                    except Exception as e:
                        self._error(500, f"could not start a session: {e}", messages[0].get("id"))
                        return
                    with listener.lock:
                        listener.sessions[sid] = session
                    headers["Mcp-Session-Id"] = sid
                    _log(f"session {sid[:8]} started")
                else:
                    session = self._session()
                    if session is None:
                        return

                requests = [m for m in messages if "method" in m and "id" in m]
                waiters = [(m["id"], session.expect(m["id"])) for m in requests]
                for m in messages:
                    session.send(m)
                if not waiters:
                    self._send(202, None, headers)
                    return
                replies = []
                for request_id, w in waiters:
                    if not w["done"].wait(REPLY_TIMEOUT) or w["reply"] is None:
                        replies.append({"jsonrpc": "2.0", "id": request_id,
                                        "error": {"code": -32603, "message": "no reply from the MCP server"}})
                    else:
                        replies.append(w["reply"])
                self._send(200, replies if isinstance(body, list) else replies[0], headers)

            def do_GET(self):
                if not self._checks_pass():
                    return
                if "text/event-stream" not in self.headers.get("Accept", ""):
                    self._send(406, {"error": "GET needs Accept: text/event-stream"})
                    return
                session = self._session()
                if session is None:
                    return
                with session.lock:
                    if session.has_stream:
                        self._send(409, {"error": "this session already has an event stream"})
                        return
                    session.has_stream = True
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                try:
                    while True:
                        try:
                            msg = session.events.get(timeout=15)
                        except queue.Empty:
                            self.wfile.write(b": keep-alive\n\n")
                            self.wfile.flush()
                            continue
                        if msg is None:
                            return
                        self.wfile.write(b"event: message\ndata: " +
                                         json.dumps(msg, separators=(",", ":")).encode() + b"\n\n")
                        self.wfile.flush()
                except OSError:
                    pass
                finally:
                    with session.lock:
                        session.has_stream = False

            def do_DELETE(self):
                if not self._checks_pass():
                    return
                session = self._session()
                if session is None:
                    return
                with listener.lock:
                    listener.sessions.pop(session.id, None)
                session.close()
                _log(f"session {session.id[:8]} ended by the client")
                self._send(200, None)

        return Handler


def _is_loopback(host: str) -> bool:
    if host in ("localhost", ""):
        return host == "localhost"
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False
