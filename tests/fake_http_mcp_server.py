"""A tiny MCP server speaking Streamable HTTP, for tests (runs in a thread).

Like fake_mcp_server.py, it appends every tools/call it actually receives to a log file.
tools/call replies come back as an SSE stream, everything else as plain JSON, so both
reply styles are exercised. It insists on a bearer token and on the session id.
"""

import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOOLS = [{"name": n, "description": n, "inputSchema": {"type": "object"}}
         for n in ("read_file", "write_file", "delete_file")]


class FakeHttpMcpServer:
    def __init__(self, log_path, token: str | None = None):
        self.log_path = log_path
        self.token = token
        self.session_id: str | None = None
        self.session_checked = False
        self.fail_method: tuple[str, int] | None = None   # (method, HTTP status) to fail once
        self.deleted = threading.Event()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/mcp"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def _handler(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, status, body=b"", ctype="application/json", headers=None):
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

            def _authorized(self):
                if server.token and self.headers.get("Authorization") != f"Bearer {server.token}":
                    self._send(401, b'{"error":"unauthorized"}')
                    return False
                return True

            def do_GET(self):
                self._send(405)

            def do_DELETE(self):
                if self._authorized() and self.headers.get("Mcp-Session-Id") == server.session_id:
                    server.deleted.set()
                    self._send(200)

            def do_POST(self):
                if not self._authorized():
                    return
                msg = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if server.fail_method and msg.get("method") == server.fail_method[0]:
                    status, server.fail_method = server.fail_method[1], None
                    self._send(status, b"boom", "text/plain")
                    return
                method, msg_id = msg.get("method"), msg.get("id")
                if method == "initialize":
                    server.session_id = uuid.uuid4().hex
                    result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                              "serverInfo": {"name": "fake-http", "version": "0"}}
                    body = json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result}).encode()
                    self._send(200, body, headers={"Mcp-Session-Id": server.session_id})
                    return
                if self.headers.get("Mcp-Session-Id") != server.session_id:
                    self._send(400, b'{"error":"missing or wrong session"}')
                    return
                server.session_checked = True
                if method is None or msg_id is None:          # notification or response
                    self._send(202)
                    return
                if method == "tools/call":
                    with open(server.log_path, "a", encoding="utf-8") as f:
                        f.write(json.dumps(msg["params"]) + "\n")
                    reply = {"jsonrpc": "2.0", "id": msg_id, "result": {
                        "content": [{"type": "text", "text": f"executed {msg['params']['name']}"}]}}
                    # SSE: a keep-alive comment, an event with no data, then the reply.
                    body = (": keep-alive\n\nevent: ping\n\n"
                            f"event: message\nid: 1\ndata: {json.dumps(reply)}\n\n").encode()
                    self._send(200, body, "text/event-stream")
                    return
                result = {"tools": TOOLS} if method == "tools/list" else {}
                self._send(200, json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result}).encode())

        return Handler
