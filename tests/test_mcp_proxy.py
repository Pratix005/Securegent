"""End-to-end tests: a client talks to the real proxy process, which wraps a fake MCP server."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FAKE_SERVER = Path(__file__).resolve().parent / "fake_mcp_server.py"

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fake_http_mcp_server import FakeHttpMcpServer  # noqa: E402

POLICY = {"sources": [{"tool": "fake.read_file", "label": "confidential"}], "rules": [
    {"id": "no-leak", "tool": "fake.write_file",
     "when": [{"arg": "content", "op": "tainted", "value": "confidential"}], "effect": "deny",
     "reason": "copies data read from a file"},
    {"id": "no-secrets", "tool": "fake.*",
     "when": [{"arg": "path", "op": "contains", "value": ".env"}], "effect": "deny", "reason": "secret file"},
    {"id": "read", "tool": "fake.read_file", "effect": "allow", "reason": "reading is fine"},
    {"id": "write", "tool": "fake.write_file", "effect": "allow", "reason": "writes ok",
     "limit": {"max": 2, "window_seconds": 3600}},
]}


class ProxyHarness(unittest.TestCase):
    """Starts the proxy around a fake server; tests talk to it as an MCP client."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        tmp = Path(self.tmp.name)
        self.executed = tmp / "executed.jsonl"
        self.audit = tmp / "audit.jsonl"
        self.kill = tmp / "KILL"
        policy = tmp / "policy.json"
        policy.write_text(json.dumps(POLICY), encoding="utf-8")
        upstream_args, env = self.upstream()
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "securegent.mcp", "--policy", str(policy), "--server-name", "fake",
             "--scopes", "fake.read_file,fake.write_file", "--audit", str(self.audit),
             "--kill-switch", str(self.kill), "--usage-db", str(tmp / "usage.db"), *upstream_args],
            cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env={**os.environ, **env})
        self.next_id = 0
        self.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                    "clientInfo": {"name": "test", "version": "0"}})
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def upstream(self):
        """CLI args that name the upstream server, and extra environment for the proxy."""
        return ["--", sys.executable, str(FAKE_SERVER), str(self.executed)], {}

    def tearDown(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=10)
        self.proc.stdout.close()
        self.tmp.cleanup()

    def send(self, msg):
        self.proc.stdin.write((json.dumps(msg) + "\n").encode())
        self.proc.stdin.flush()

    def request(self, method, params):
        self.next_id += 1
        self.send({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params})
        reply = json.loads(self.proc.stdout.readline())
        self.assertEqual(reply["id"], self.next_id)
        return reply["result"]

    def call(self, name, **args):
        return self.request("tools/call", {"name": name, "arguments": args})

    def executed_calls(self):
        if not self.executed.exists():
            return []
        return [json.loads(l)["name"] for l in self.executed.read_text(encoding="utf-8").splitlines()]

class McpProxyTests(ProxyHarness):
    def test_out_of_scope_tools_are_hidden(self):
        names = [t["name"] for t in self.request("tools/list", {})["tools"]]
        self.assertEqual(names, ["read_file", "write_file"])

    def test_allowed_call_reaches_server(self):
        result = self.call("read_file", path="notes.txt")
        self.assertNotIn("isError", result)
        self.assertEqual(self.executed_calls(), ["read_file"])

    def test_policy_block_never_reaches_server(self):
        result = self.call("read_file", path="config/.env")
        self.assertTrue(result["isError"])
        self.assertIn("secret file", result["content"][0]["text"])
        self.assertEqual(self.executed_calls(), [])

    def test_out_of_scope_call_blocked_even_if_client_ignores_list(self):
        result = self.call("delete_file", path="x")
        self.assertTrue(result["isError"])
        self.assertEqual(self.executed_calls(), [])

    def test_running_limit(self):
        self.call("write_file", path="a")
        self.call("write_file", path="b")
        self.assertTrue(self.call("write_file", path="c")["isError"])
        self.assertEqual(self.executed_calls(), ["write_file", "write_file"])

    def test_taint_from_upstream_results(self):
        self.call("write_file", path="a", content="executed read_file")   # nothing read yet: fine
        self.call("read_file", path="notes.txt")         # fake server answers "executed read_file"
        self.assertTrue(self.call("write_file", path="b", content="executed read_file")["isError"])
        self.assertEqual(self.executed_calls(), ["write_file", "read_file"])

    def test_kill_switch_file(self):
        self.kill.write_text("stop")
        self.assertTrue(self.call("read_file", path="a")["isError"])
        self.kill.unlink()
        self.assertNotIn("isError", self.call("read_file", path="a"))

    def test_batch_calls_are_each_checked(self):
        self.send([{"jsonrpc": "2.0", "id": 100, "method": "tools/call",
                    "params": {"name": "read_file", "arguments": {"path": "ok.txt"}}},
                   {"jsonrpc": "2.0", "id": 101, "method": "tools/call",
                    "params": {"name": "read_file", "arguments": {"path": ".env"}}}])
        replies = {r["id"]: r["result"] for r in (json.loads(self.proc.stdout.readline()) for _ in range(2))}
        self.assertTrue(replies[101]["isError"])
        self.assertNotIn("isError", replies[100])
        self.assertEqual(self.executed_calls(), ["read_file"])

    def test_every_decision_is_audited(self):
        self.call("read_file", path="ok.txt")
        self.call("read_file", path=".env")
        entries = [json.loads(l) for l in self.audit.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([(e["tool"], e["decision"]) for e in entries],
                         [("fake.read_file", "allow"), ("fake.read_file", "deny")])


class McpProxyHttpTests(McpProxyTests):
    """The same tests, with the server reached over Streamable HTTP (JSON and SSE replies,
    session ids, auth header from an environment variable)."""

    def upstream(self):
        self.server = FakeHttpMcpServer(self.executed, token="s3cret")
        return (["--upstream-url", self.server.url, "--header", "Authorization: Bearer ${FAKE_MCP_TOKEN}"],
                {"FAKE_MCP_TOKEN": "s3cret"})

    def tearDown(self):
        super().tearDown()
        self.server.stop()

    def test_session_is_used_and_closed(self):
        self.call("read_file", path="a")
        self.assertTrue(self.server.session_checked)
        self.proc.stdin.close()
        self.proc.wait(timeout=10)
        self.assertTrue(self.server.deleted.wait(5))
        self.proc.stdin = open(os.devnull, "wb")      # so tearDown can close it again

    def test_upstream_http_error_becomes_jsonrpc_error(self):
        self.server.fail_method = ("tools/list", 500)
        self.next_id += 1
        self.send({"jsonrpc": "2.0", "id": self.next_id, "method": "tools/list", "params": {}})
        reply = json.loads(self.proc.stdout.readline())
        self.assertEqual(reply["id"], self.next_id)
        self.assertIn("HTTP 500", reply["error"]["message"])


class PoisonedServerTests(ProxyHarness):
    def upstream(self):
        return ["--", sys.executable, str(FAKE_SERVER), str(self.executed), "poisoned"], {}

    def test_poisoned_tool_is_hidden_and_refused(self):
        names = [t["name"] for t in self.request("tools/list", {})["tools"]]
        self.assertEqual(names, ["write_file"])
        result = self.call("read_file", path="notes.txt")
        self.assertTrue(result["isError"])
        self.assertIn("tool poisoning", result["content"][0]["text"])
        self.assertEqual(self.executed_calls(), [])
        entries = [json.loads(l) for l in self.audit.read_text(encoding="utf-8").splitlines()]
        scan = [e for e in entries if e.get("stage") == "tool-scan"]
        self.assertIn("hidden-instruction tag", scan[0]["reason"])
        self.assertIn("secret file access", scan[0]["reason"])


class RugPullTests(ProxyHarness):
    def upstream(self):
        return ["--", sys.executable, str(FAKE_SERVER), str(self.executed), "rugpull"], {}

    def test_tool_changed_after_first_list_is_blocked(self):
        first = [t["name"] for t in self.request("tools/list", {})["tools"]]
        self.assertEqual(first, ["read_file", "write_file"])
        self.assertNotIn("isError", self.call("read_file", path="a"))
        second = [t["name"] for t in self.request("tools/list", {})["tools"]]
        self.assertEqual(second, ["write_file"])
        self.assertTrue(self.call("read_file", path="a")["isError"])
        self.assertEqual(self.executed_calls(), ["read_file"])


class HttpUpstreamUnitTests(unittest.TestCase):
    def test_headers_read_env_vars_and_reject_missing_ones(self):
        from securegent.mcp.upstream import parse_headers
        os.environ["SG_TEST_TOKEN"] = "abc"
        self.assertEqual(parse_headers(["Authorization: Bearer ${SG_TEST_TOKEN}"]),
                         {"Authorization": "Bearer abc"})
        with self.assertRaises(ValueError):
            parse_headers(["X-Key: ${SG_TEST_NOT_SET_ANYWHERE}"])
        with self.assertRaises(ValueError):
            parse_headers(["no colon here"])


class FilesystemPolicyTests(unittest.TestCase):
    """Decisions of the bundled pack:mcp-filesystem (no server needed)."""

    def setUp(self):
        sys.path.insert(0, str(ROOT))
        from securegent.policy import Policy
        self.policy = Policy.from_file("pack:mcp-filesystem")

    def effect(self, tool, **args):
        return self.policy.evaluate("mcp-agent", f"filesystem.{tool}", args).effect

    def test_reads(self):
        self.assertEqual(self.effect("read_text_file", path="C:/work/notes.txt"), "allow")
        self.assertEqual(self.effect("list_directory", path="C:/work"), "allow")
        for secret in ["C:/work/.env", "C:/Users/me/.ssh/id_rsa", "C:/work/server.key", "C:/work/Passwords.txt"]:
            self.assertEqual(self.effect("read_text_file", path=secret), "deny", secret)
        self.assertEqual(self.effect("read_multiple_files", paths=["C:/work/a.txt", "C:/work/.env"]), "deny")

    def test_writes(self):
        self.assertEqual(self.effect("write_file", path="C:/work/drafts/idea.md", content="x"), "allow")
        self.assertEqual(self.effect("write_file", path=r"C:\work\drafts\idea.md", content="x"), "allow")
        self.assertEqual(self.effect("write_file", path="C:/work/notes.txt", content="x"), "deny")
        self.assertEqual(self.effect("write_file", path="C:/work/drafts/../notes.txt", content="x"), "deny")
        self.assertEqual(self.effect("write_file", path="C:/work/drafts/.env", content="x"), "deny")
        self.assertEqual(self.effect("append_file", path="C:/work/drafts/log.md", content="x"), "allow")
        self.assertEqual(self.effect("append_file", path="C:/work/notes.txt", content="x"), "deny")

    def test_other_tools(self):
        self.assertEqual(self.effect("move_file", source="C:/work/a", destination="C:/work/b"), "approve")
        self.assertEqual(self.effect("copy_file", source="C:/work/.env", destination="C:/work/drafts/x"), "approve")
        self.assertEqual(self.effect("some_new_tool", path="C:/work/a"), "deny")


if __name__ == "__main__":
    unittest.main()
