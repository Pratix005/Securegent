"""The proxy serving Streamable HTTP (--listen), wrapping the fake stdio MCP server."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FAKE_SERVER = Path(__file__).resolve().parent / "fake_mcp_server.py"
POLICY = {"rules": [
    {"id": "no-secrets", "tool": "fake.*", "when": [{"arg": "path", "op": "contains", "value": ".env"}],
     "effect": "deny", "reason": "secret file"},
    {"id": "ok", "tool": "fake.*", "effect": "allow", "reason": "fine"},
]}
INIT = {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}


class ListenTests(unittest.TestCase):
    token = None

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        tmp = Path(self.tmp.name)
        self.executed = tmp / "executed.jsonl"
        policy = tmp / "policy.json"
        policy.write_text(json.dumps(POLICY), encoding="utf-8")
        env = {**os.environ}
        env.pop("SECUREGENT_LISTEN_TOKEN", None)
        if self.token:
            env["SECUREGENT_LISTEN_TOKEN"] = self.token
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "securegent.mcp", "--policy", str(policy), "--server-name", "fake",
             "--scopes", "fake.read_file,fake.write_file", "--audit", str(tmp / "audit.jsonl"),
             "--kill-switch", str(tmp / "KILL"), "--usage-db", "memory", "--listen", "127.0.0.1:0",
             "--", sys.executable, str(FAKE_SERVER), str(self.executed)],
            cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env)
        self.url = None
        for line in self.proc.stderr:
            text = line.decode(errors="replace")
            if "listening on " in text:
                self.url = text.split("listening on ", 1)[1].strip()
                break
        self.assertIsNotNone(self.url, "proxy did not start listening")
        self.id = 0

    def tearDown(self):
        self.proc.terminate()
        self.proc.wait(timeout=10)
        self.proc.stderr.close()
        self.tmp.cleanup()

    # --- a minimal Streamable HTTP client ----------------------------------------------
    def post(self, body, session=None, headers=None):
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        if session:
            h["Mcp-Session-Id"] = session
        h.update(headers or {})
        req = urllib.request.Request(self.url, data=json.dumps(body).encode(), headers=h, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                data = r.read()
                return r.status, (json.loads(data) if data else None), r.headers
        except urllib.error.HTTPError as e:
            return e.code, None, e.headers

    def rpc(self, method, params, session=None):
        self.id += 1
        return self.post({"jsonrpc": "2.0", "id": self.id, "method": method, "params": params}, session)

    def open_session(self):
        status, reply, headers = self.rpc("initialize", INIT)
        self.assertEqual(status, 200)
        self.assertEqual(reply["result"]["serverInfo"]["name"], "fake")
        sid = headers["Mcp-Session-Id"]
        status, _, _ = self.post({"jsonrpc": "2.0", "method": "notifications/initialized"}, sid)
        self.assertEqual(status, 202)
        return sid

    def executed_calls(self):
        if not self.executed.exists():
            return []
        return [json.loads(l)["name"] for l in self.executed.read_text(encoding="utf-8").splitlines()]

    # --- tests ---------------------------------------------------------------------------
    def test_session_flow_and_policy(self):
        sid = self.open_session()
        tools = [t["name"] for t in self.rpc("tools/list", {}, sid)[1]["result"]["tools"]]
        self.assertEqual(tools, ["read_file", "write_file"])
        ok = self.rpc("tools/call", {"name": "read_file", "arguments": {"path": "a.txt"}}, sid)[1]
        self.assertNotIn("isError", ok["result"])
        bad = self.rpc("tools/call", {"name": "read_file", "arguments": {"path": ".env"}}, sid)[1]
        self.assertTrue(bad["result"]["isError"])
        self.assertEqual(self.executed_calls(), ["read_file"])

    def test_batch_returns_a_list(self):
        sid = self.open_session()
        status, replies, _ = self.post([
            {"jsonrpc": "2.0", "id": "a", "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "x"}}},
            {"jsonrpc": "2.0", "id": "b", "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": ".env"}}},
        ], sid)
        self.assertEqual(status, 200)
        by_id = {r["id"]: r for r in replies}
        self.assertNotIn("isError", by_id["a"]["result"])
        self.assertTrue(by_id["b"]["result"]["isError"])

    def test_session_header_is_required_and_delete_ends_it(self):
        self.assertEqual(self.rpc("tools/list", {})[0], 400)
        self.assertEqual(self.rpc("tools/list", {}, "0" * 32)[0], 404)
        sid = self.open_session()
        h = {"Mcp-Session-Id": sid}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(self.url, headers=h, method="DELETE")
        with urllib.request.urlopen(req, timeout=10) as r:
            self.assertEqual(r.status, 200)
        self.assertEqual(self.rpc("tools/list", {}, sid)[0], 404)

    def test_sessions_are_separate(self):
        a, b = self.open_session(), self.open_session()
        self.assertNotEqual(a, b)
        self.assertEqual(self.rpc("tools/list", {}, a)[0], 200)
        self.assertEqual(self.rpc("tools/list", {}, b)[0], 200)

    def test_foreign_origin_is_refused(self):
        status, _, _ = self.post({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": INIT},
                                 headers={"Origin": "https://evil.example"})
        self.assertEqual(status, 403)
        status, _, _ = self.post({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": INIT},
                                 headers={"Origin": "http://localhost:3000"})
        self.assertEqual(status, 200)


class ListenTokenTests(ListenTests):
    token = "listen-secret"

    def test_wrong_or_missing_token_is_refused(self):
        good, self.token = self.token, None
        try:
            self.assertEqual(self.rpc("initialize", INIT)[0], 401)
            self.token = "wrong"
            self.assertEqual(self.rpc("initialize", INIT)[0], 401)
        finally:
            self.token = good


class ListenSafetyTests(unittest.TestCase):
    def test_non_loopback_without_token_refuses_to_start(self):
        env = {k: v for k, v in os.environ.items() if k != "SECUREGENT_LISTEN_TOKEN"}
        out = subprocess.run([sys.executable, "-m", "securegent.mcp", "--policy", "pack:mcp-filesystem",
                              "--server-name", "fs", "--usage-db", "memory", "--listen", "0.0.0.0:0",
                              "--", sys.executable, str(FAKE_SERVER), "x"],
                             cwd=ROOT, capture_output=True, text=True, timeout=30, env=env)
        self.assertEqual(out.returncode, 2)
        self.assertIn("SECUREGENT_LISTEN_TOKEN", out.stderr)


if __name__ == "__main__":
    unittest.main()
