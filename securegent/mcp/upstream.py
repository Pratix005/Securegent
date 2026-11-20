"""
How the proxy talks to the real MCP server.

  StdioUpstream - starts the server as a child process; newline-delimited JSON-RPC on
                  its stdin/stdout.
  HttpUpstream  - a remote server using the Streamable HTTP transport (MCP spec
                  2025-03-26 and later): every message is POSTed to one URL; replies come
                  back as JSON or as a server-sent event (SSE) stream.

Both deliver server messages to `on_message(msg)` and call `on_closed()` when the
connection is gone. Standard library only.
"""

import json
import os
import re
import shutil
import subprocess  # nosec B404: runs the MCP server command the user configured
import sys
import threading
import urllib.error
import urllib.request
from typing import Callable

OnMessage = Callable[[object], None]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: urllib would re-send our headers, including any
    Authorization token, to whatever host the server redirects to."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None                      # urllib then raises HTTPError with the 3xx code


_OPENER = urllib.request.build_opener(_NoRedirect)


def _log(msg: str) -> None:
    print(f"[securegent] {msg}", file=sys.stderr, flush=True)


class StdioUpstream:
    def __init__(self, command: list[str]):
        self.command = command
        self.proc: subprocess.Popen | None = None
        self._lock = threading.Lock()

    def describe(self) -> str:
        return " ".join(self.command)

    def start(self, on_message: OnMessage, on_raw: Callable[[bytes], None], on_closed: Callable[[], None]) -> None:
        exe = shutil.which(self.command[0]) or self.command[0]   # resolves npx -> npx.cmd on Windows
        self.proc = subprocess.Popen([exe, *self.command[1:]], stdin=subprocess.PIPE,  # nosec B603: user-configured MCP server command, list form, no shell
                                     stdout=subprocess.PIPE, bufsize=0)

        def loop():
            try:
                for raw in self.proc.stdout:
                    line = raw.strip()
                    if not line:
                        continue
                    try:
                        msg = json.loads(line)
                    except json.JSONDecodeError:
                        on_raw(line)                 # not ours to judge; pass it on
                        continue
                    on_message(msg)
            except (OSError, ValueError):
                pass
            finally:
                on_closed()
        threading.Thread(target=loop, daemon=True).start()

    def send(self, msg) -> None:
        data = json.dumps(msg, separators=(",", ":")).encode() + b"\n"
        with self._lock:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()

    def close(self) -> int:
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            return self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            return self.proc.wait()


_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def parse_headers(items: list[str] | None) -> dict[str, str]:
    """["Authorization: Bearer ${GITHUB_TOKEN}"] -> {...}; ${VAR} is read from the
    environment so secrets don't have to sit in config files or process listings."""
    headers = {}
    for item in items or []:
        name, sep, value = item.partition(":")
        if not sep or not name.strip():
            raise ValueError(f"header must look like 'Name: value', got {item!r}")

        def env(m):
            if m.group(1) not in os.environ:
                raise ValueError(f"header {name.strip()} uses ${{{m.group(1)}}}, which is not set")
            return os.environ[m.group(1)]
        headers[name.strip()] = _ENV_REF.sub(env, value.strip())
    return headers


class HttpUpstream:
    """Client side of MCP Streamable HTTP. One proxy = one MCP session."""

    def __init__(self, url: str, headers: dict[str, str] | None = None, timeout: float = 300):
        if not url.startswith(("http://", "https://")):
            raise ValueError("upstream URL must start with http:// or https://")
        self.url = url
        self.headers = dict(headers or {})
        self.timeout = timeout
        self.session_id: str | None = None
        self.protocol_version: str | None = None
        self._on_message: OnMessage = lambda m: None
        self._on_closed: Callable[[], None] = lambda: None
        self._closed = threading.Event()
        self._listening = False
        self._lock = threading.Lock()

    def describe(self) -> str:
        return self.url

    def start(self, on_message: OnMessage, on_raw, on_closed: Callable[[], None]) -> None:
        self._on_message, self._on_closed = on_message, on_closed

    # --- requests -----------------------------------------------------------------
    def _request(self, method: str, body: bytes | None = None, accept: str = "application/json, text/event-stream"):
        headers = {**self.headers, "Accept": accept}
        if body is not None:
            headers["Content-Type"] = "application/json"
        with self._lock:
            if self.session_id:
                headers["Mcp-Session-Id"] = self.session_id
            if self.protocol_version:
                headers["MCP-Protocol-Version"] = self.protocol_version
        req = urllib.request.Request(self.url, data=body, headers=headers, method=method)
        return _OPENER.open(req, timeout=self.timeout)

    def send(self, msg) -> None:
        # One thread per POST: a slow tool call must not hold up pings or other calls.
        threading.Thread(target=self._post, args=(msg,), daemon=True).start()

    def _post(self, msg) -> None:
        ids = [m["id"] for m in (msg if isinstance(msg, list) else [msg])
               if isinstance(m, dict) and "id" in m and "method" in m]
        is_init = isinstance(msg, dict) and msg.get("method") == "initialize"
        try:
            resp = self._request("POST", json.dumps(msg, separators=(",", ":")).encode())
        except urllib.error.HTTPError as e:
            detail = e.read(300).decode("utf-8", "replace").strip()
            if e.code == 404 and self.session_id:
                detail = "the server ended the MCP session; restart the client to reconnect"
            elif 300 <= e.code < 400:
                detail = (f"redirect to {e.headers.get('Location', '?')} not followed, so headers "
                          "and tokens stay with the configured URL; use the final URL in --upstream-url")
            self._fail(ids, f"upstream HTTP {e.code}: {detail or e.reason}")
            return
        except (urllib.error.URLError, OSError, ValueError) as e:
            self._fail(ids, f"upstream unreachable: {getattr(e, 'reason', e)}")
            return

        with resp:
            if is_init:
                sid = resp.headers.get("Mcp-Session-Id")
                with self._lock:
                    if sid:
                        self.session_id = sid
            ctype = (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if resp.status == 202 or not ids:
                return
            try:
                if ctype == "text/event-stream":
                    for m in self._read_sse(resp):
                        self._deliver(m, is_init)
                else:
                    data = resp.read()
                    if data.strip():
                        self._deliver(json.loads(data), is_init)
            except (OSError, ValueError) as e:
                self._fail(ids, f"bad reply from upstream: {e}")
                return
        if is_init:
            self._start_listening()

    def _deliver(self, msg, is_init: bool) -> None:
        for m in (msg if isinstance(msg, list) else [msg]):
            if is_init and isinstance(m, dict) and isinstance(m.get("result"), dict):
                with self._lock:
                    self.protocol_version = m["result"].get("protocolVersion") or self.protocol_version
            self._on_message(m)

    def _fail(self, ids: list, reason: str) -> None:
        _log(reason)
        for request_id in ids:
            self._on_message({"jsonrpc": "2.0", "id": request_id,
                              "error": {"code": -32603, "message": reason}})

    @staticmethod
    def _read_sse(resp):
        """Yield the JSON messages in an SSE stream (events without data are skipped)."""
        data: list[str] = []
        for raw in resp:
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if line == "":
                if data:
                    text = "\n".join(data)
                    data = []
                    try:
                        yield json.loads(text)
                    except json.JSONDecodeError:
                        _log("skipped an upstream event that is not JSON")
                continue
            if line.startswith(":"):
                continue                        # comment / keep-alive
            field, _, value = line.partition(":")
            if field == "data":
                data.append(value[1:] if value.startswith(" ") else value)
        if data:
            try:
                yield json.loads("\n".join(data))
            except json.JSONDecodeError:
                pass

    def _start_listening(self) -> None:
        """Optional GET stream for messages the server starts (notifications, requests)."""
        if self._listening:
            return
        self._listening = True

        def listen():
            failures = 0
            while not self._closed.is_set() and failures < 3:
                try:
                    with self._request("GET", accept="text/event-stream") as resp:
                        if not (resp.headers.get("Content-Type") or "").startswith("text/event-stream"):
                            return
                        for m in self._read_sse(resp):
                            if self._closed.is_set():
                                return
                            failures = 0
                            self._on_message(m)
                    failures += 1           # stream ended: reconnect, but not forever
                    self._closed.wait(1)
                except urllib.error.HTTPError:
                    return                  # 405 = server doesn't offer one; that's allowed
                except (urllib.error.URLError, OSError, ValueError):
                    failures += 1           # idle timeout or dropped connection: reconnect
                    self._closed.wait(1)
        threading.Thread(target=listen, daemon=True).start()

    def close(self) -> int:
        self._closed.set()
        if self.session_id:
            try:
                self._request("DELETE", accept="application/json").close()
            except (urllib.error.URLError, OSError, ValueError):
                pass
        return 0
