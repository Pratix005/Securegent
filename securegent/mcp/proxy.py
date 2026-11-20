"""
Securegent MCP proxy.

Sits between an MCP client (Claude Desktop, Claude Code, Cursor, ...) and an MCP
server. The client talks to the proxy over stdio; the server can be a local command
(stdio) or a remote URL (Streamable HTTP), see upstream.py:

    client  <--stdio-->  McpProxy  <--stdio or HTTP-->  upstream MCP server

Every `tools/call` is checked by the Securegent Guard before it reaches the server.
Blocked calls never reach the server; the client gets a tool result with isError=true
explaining why, so the model sees the refusal. Everything else is passed through.

Tool names are namespaced for policies as "<server_name>.<tool>", e.g.
"filesystem.write_file", so one policy file can cover many servers.
"""

import json
import threading
from pathlib import Path
from typing import BinaryIO

from ..guard import Blocked, Guard
from .upstream import HttpUpstream, StdioUpstream, _log


class McpProxy:
    def __init__(self, upstream: "list[str] | StdioUpstream | HttpUpstream", guard: Guard, token: str,
                 server_name: str, client_in: BinaryIO, client_out: BinaryIO,
                 hide_out_of_scope_tools: bool = True, kill_switch: str | Path | None = None):
        # A plain command list means "start this local stdio server".
        self.upstream = StdioUpstream(upstream) if isinstance(upstream, list) else upstream
        self.guard = guard
        self.token = token
        self.server = server_name
        self.client_in = client_in
        self.client_out = client_out
        self.hide_tools = hide_out_of_scope_tools
        self.kill_switch = Path(kill_switch) if kill_switch else None
        self._agent_id = guard.registry.verify(token)["sub"]
        self._write_lock = threading.Lock()
        self._pending_lists: set = set()        # ids of tools/list requests in flight
        self._pending_calls: dict = {}          # id -> (tool, args) of allowed calls in flight
        self._done = threading.Event()

    # --- plumbing -------------------------------------------------------------------
    def _send_client(self, msg) -> None:
        data = json.dumps(msg, separators=(",", ":")).encode() + b"\n"
        with self._write_lock:
            self.client_out.write(data)
            self.client_out.flush()

    def _send_upstream(self, msg) -> None:
        self.upstream.send(msg)

    def _send_client_raw(self, line: bytes) -> None:
        with self._write_lock:
            self.client_out.write(line + b"\n")
            self.client_out.flush()

    def run(self) -> int:
        self.upstream.start(self._handle_upstream_message, self._send_client_raw, self._done.set)
        _log(f"proxying '{self.server}': {self.upstream.describe()}")
        threading.Thread(target=self._client_loop, daemon=True).start()
        self._done.wait()
        return self.upstream.close()

    # --- client -> server -------------------------------------------------------------
    def _client_loop(self) -> None:
        try:
            for raw in self.client_in:
                line = raw.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    _log("dropped a message from the client that is not valid JSON")
                    continue
                # Split batches so every call inside one is checked on its own.
                for m in (msg if isinstance(msg, list) else [msg]):
                    if isinstance(m, dict):
                        self._handle_client_message(m)
        except (OSError, ValueError):
            pass
        finally:
            self._done.set()

    def _handle_client_message(self, msg: dict) -> None:
        method = msg.get("method")
        if method == "tools/call":
            # Its own thread: a call waiting for human approval must not freeze
            # pings, cancellations or other calls.
            threading.Thread(target=self._handle_tool_call_safely, args=(msg,), daemon=True).start()
            return
        if method == "tools/list" and "id" in msg:
            try:
                self._pending_lists.add(msg["id"])
            except TypeError:
                pass
        # We re-serialise what we parsed, so the server sees exactly what was checked.
        self._send_upstream(msg)

    def _handle_tool_call_safely(self, msg: dict) -> None:
        try:
            self._handle_tool_call(msg)
        except (OSError, ValueError):
            pass                                   # pipes closed while shutting down
        except Exception as e:                     # never forward a call we failed to check
            _log(f"error while checking a call, refusing it: {type(e).__name__}: {e}")
            if "id" in msg:
                try:
                    self._refuse(msg["id"], "internal error while checking this call")
                except (OSError, ValueError):
                    pass

    def _handle_tool_call(self, msg: dict) -> None:
        if "id" not in msg:
            _log("dropped a tools/call sent as a notification (no id)")
            return
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        name, args = params.get("name"), params.get("arguments", {})
        if args is None:
            args = {}
        if not isinstance(name, str) or not isinstance(args, dict):
            self._refuse(msg["id"], "malformed tools/call request")
            return

        self._apply_kill_switch()
        tool = f"{self.server}.{name}"
        try:
            self.guard.check(self.token, tool, args)
        except Blocked as e:
            _log(f"BLOCKED {tool} {_short(args)}: {e}")
            self._refuse(msg["id"], str(e))
            return
        _log(f"allowed {tool} {_short(args)}")
        try:
            self._pending_calls[msg["id"]] = (tool, args)   # so taint tracking sees the result
        except TypeError:
            pass
        self._send_upstream(msg)

    def _refuse(self, request_id, reason: str) -> None:
        self._send_client({"jsonrpc": "2.0", "id": request_id, "result": {
            "content": [{"type": "text", "text": f"BLOCKED by Securegent security policy: {reason}. "
                                                 "Do not try to work around this."}],
            "isError": True,
        }})

    def _apply_kill_switch(self) -> None:
        if self.kill_switch is None:
            return
        if self.kill_switch.exists():
            self.guard.registry.disable(self._agent_id)
        else:
            self.guard.registry.enable(self._agent_id)

    # --- server -> client -------------------------------------------------------------
    def _handle_upstream_message(self, msg) -> None:
        if isinstance(msg, dict):
            self._observe_result(msg)
            if self.hide_tools:
                msg = self._filter_tool_list(msg)
        try:
            self._send_client(msg)
        except (OSError, ValueError):
            self._done.set()                       # the client went away

    def _observe_result(self, msg: dict) -> None:
        """Pass a tool result to the guard before the client (and model) sees it."""
        try:
            pending = self._pending_calls.pop(msg.get("id"), None)
        except TypeError:
            return
        if pending is None or not isinstance(msg.get("result"), dict):
            return
        tool, args = pending
        result = msg["result"]
        parts = [c.get("text", "") for c in result.get("content", []) if isinstance(c, dict)]
        if result.get("structuredContent") is not None:
            parts.append(json.dumps(result["structuredContent"], default=str))
        try:
            self.guard.observe(self.token, tool, args, "\n".join(parts))
        except Exception as e:                 # never break the stream over bookkeeping
            _log(f"could not record result of {tool} for taint tracking: {e}")

    def _filter_tool_list(self, msg: dict) -> dict:
        """Hide tools the agent's token can never use, so the model doesn't try them."""
        try:
            is_list_reply = msg.get("id") in self._pending_lists
        except TypeError:
            return msg
        if not is_list_reply:
            return msg
        self._pending_lists.discard(msg["id"])
        result = msg.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            return msg
        try:
            claims = self.guard.registry.verify(self.token)
        except Exception:
            return msg
        kept, hidden = [], []
        for t in result["tools"]:
            name = t.get("name") if isinstance(t, dict) else None
            if name and self.guard.registry.has_scope(claims, f"{self.server}.{name}"):
                kept.append(t)
            else:
                hidden.append(name)
        if hidden:
            _log(f"hid {len(hidden)} tool(s) outside the agent's scope: {', '.join(map(str, hidden))}")
        return {**msg, "result": {**result, "tools": kept}}


def _short(args: dict, limit: int = 120) -> str:
    s = json.dumps(args, default=str)
    return s if len(s) <= limit else s[:limit] + "..."
