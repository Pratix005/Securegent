"""A tiny stdio MCP server for tests. Usage: python fake_mcp_server.py <executed-log-file>

Every tools/call it actually receives is appended to the log file, so tests can prove
that blocked calls never reached the server.
"""

import json
import sys

LOG = sys.argv[1]
TOOLS = [{"name": n, "description": n, "inputSchema": {"type": "object"}}
         for n in ("read_file", "write_file", "delete_file")]


def reply(msg_id, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result}) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    if not line.strip():
        continue
    msg = json.loads(line)
    method, msg_id = msg.get("method"), msg.get("id")
    if method == "initialize":
        reply(msg_id, {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                       "serverInfo": {"name": "fake", "version": "0"}})
    elif method == "tools/list":
        reply(msg_id, {"tools": TOOLS})
    elif method == "tools/call":
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(msg["params"]) + "\n")
        reply(msg_id, {"content": [{"type": "text", "text": f"executed {msg['params']['name']}"}]})
    elif msg_id is not None:
        reply(msg_id, {})
