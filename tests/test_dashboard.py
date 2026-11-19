import http.client
import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from securegent import AgentRegistry, AuditLog, Blocked, Guard, Policy  # noqa: E402
from securegent.approvals import FileApprover, decide, list_pending  # noqa: E402
from securegent.dashboard import DashboardState, create_server  # noqa: E402


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.tmp.name)
        self.audit = AuditLog(self.state_dir / "audit.jsonl")
        self.audit.write({"tool": "pay", "args": {"vendor": "<script>alert(1)</script>"}, "decision": "deny",
                          "reason": "test"})
        self.kill = self.state_dir / "KILL_SWITCH"
        self.port = free_port()
        self.server, self.token = create_server(
            DashboardState(self.state_dir, self.audit.path, self.kill), self.port)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def req(self, method, path, body=None, token=True, host=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"Host": host or f"127.0.0.1:{self.port}"}
        if token:
            h["X-Securegent-Token"] = self.token if token is True else token
        if body is not None:
            h["Content-Type"] = "application/json"
            body = json.dumps(body)
        h.update(headers or {})
        conn.request(method, path, body=body, headers=h)
        r = conn.getresponse()
        data = r.read()
        conn.close()
        return r.status, r.getheader("Content-Security-Policy"), data

    def test_page_has_strict_csp_with_nonce(self):
        status, csp, body = self.req("GET", "/", token=False)
        self.assertEqual(status, 200)
        self.assertIn("script-src 'nonce-", csp)
        self.assertNotIn(b"{{NONCE}}", body)
        self.assertNotIn(b"innerHTML", body)          # the page must never render data as HTML

    def test_bundled_fonts_served_and_no_path_tricks(self):
        for font in ["Recursive-Variable.woff2"]:
            status, _, body = self.req("GET", f"/static/fonts/{font}", token=False)
            self.assertEqual(status, 200, font)
            self.assertEqual(body[:4], b"wOF2")
        for bad in ["/static/fonts/../server.py", "/static/fonts/..%2Fserver.py", "/static/fonts/OFL-Recursive.txt"]:
            self.assertEqual(self.req("GET", bad, token=False)[0], 404, bad)

    def test_state_requires_token(self):
        self.assertEqual(self.req("GET", "/api/state", token=False)[0], 401)
        self.assertEqual(self.req("GET", "/api/state", token="wrong")[0], 401)
        status, _, body = self.req("GET", "/api/state")
        self.assertEqual(status, 200)
        state = json.loads(body)
        self.assertEqual(state["stats"], {"total": 1, "allowed": 0, "blocked": 1})
        self.assertEqual(state["agents"], [{"name": "unidentified", "allowed": 0, "blocked": 1,
                                            "last": state["events"][0]["ts"]}])

    def test_dns_rebinding_host_rejected(self):
        self.assertEqual(self.req("GET", "/api/state", host=f"evil.com:{self.port}")[0], 403)
        self.assertEqual(self.req("GET", "/", token=False, host="evil.com")[0], 403)

    def test_cross_site_origin_rejected(self):
        status = self.req("POST", "/api/kill-switch", {"on": True}, headers={"Origin": "https://evil.com"})[0]
        self.assertEqual(status, 403)
        self.assertFalse(self.kill.exists())

    def test_simple_form_post_rejected(self):
        status = self.req("POST", "/api/kill-switch", None,
                          headers={"Content-Type": "text/plain", "Content-Length": "10"})[0]
        self.assertEqual(status, 415)

    def test_kill_switch_toggle(self):
        self.assertEqual(self.req("POST", "/api/kill-switch", {"on": True})[0], 200)
        self.assertTrue(self.kill.exists())
        self.assertTrue(json.loads(self.req("GET", "/api/state")[2])["kill_switch"])
        self.req("POST", "/api/kill-switch", {"on": False})
        self.assertFalse(self.kill.exists())

    def test_approval_round_trip(self):
        result = {}
        approver = FileApprover(self.state_dir, timeout=10, poll=0.05)
        t = threading.Thread(target=lambda: result.update(ok=approver({"tool": "pay", "reason": "big"})))
        t.start()
        for _ in range(100):
            pending = json.loads(self.req("GET", "/api/state")[2])["pending"]
            if pending:
                break
            time.sleep(0.05)
        self.assertEqual(len(pending), 1)
        self.assertEqual(self.req("POST", "/api/decide", {"id": pending[0]["id"], "approved": True})[0], 200)
        t.join(5)
        self.assertTrue(result["ok"])
        self.assertEqual(list_pending(self.state_dir), [])

    def test_decide_unknown_or_bad_id(self):
        self.assertEqual(self.req("POST", "/api/decide", {"id": "0" * 32, "approved": True})[0], 410)
        self.assertFalse(decide("../../etc/passwd", True, self.state_dir))


class ApproverTests(unittest.TestCase):
    def test_timeout_means_deny(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(FileApprover(tmp, timeout=0.3, poll=0.05)({"tool": "x"}))
            self.assertEqual(list_pending(tmp), [])

    def test_deny(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = {}
            t = threading.Thread(target=lambda: result.update(
                ok=FileApprover(tmp, timeout=5, poll=0.05)({"tool": "x"})))
            t.start()
            while not list_pending(tmp):
                time.sleep(0.02)
            decide(list_pending(tmp)[0]["id"], False, tmp)
            t.join(5)
            self.assertFalse(result["ok"])


class ConcurrencyTests(unittest.TestCase):
    def test_parallel_calls_cannot_exceed_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg = AgentRegistry(secret=b"s")
            reg.register("bot", owner="a", allowed_scopes=["pay"])
            guard = Guard(reg, Policy([{"id": "p", "tool": "pay", "effect": "allow",
                                        "limit": {"sum_arg": "amount", "max": 100, "window_seconds": 60}}]),
                          AuditLog(Path(tmp) / "a.jsonl"))
            guard.tool("pay")(lambda amount: "paid")
            token = reg.issue_token("bot", ["pay"])
            ok = []

            def worker():
                try:
                    guard.call(token, "pay", amount=10)
                    ok.append(1)
                except Blocked:
                    pass

            threads = [threading.Thread(target=worker) for _ in range(40)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            self.assertEqual(len(ok), 10)


class ProxyApprovalTests(unittest.TestCase):
    """The MCP proxy waits for the dashboard, and keeps answering other requests meanwhile."""

    def test_proxy_waits_for_approval_without_freezing(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            policy = tmp / "policy.json"
            policy.write_text(json.dumps({"rules": [
                {"id": "ask", "tool": "fake.delete_file", "effect": "approve", "reason": "deleting needs a human"}]}))
            executed = tmp / "executed.jsonl"
            proc = subprocess.Popen(
                [sys.executable, "-m", "securegent.mcp", "--policy", str(policy), "--server-name", "fake",
                 "--state-dir", str(tmp), "--approvals", "--approval-timeout", "20",
                 "--", sys.executable, str(ROOT / "tests" / "fake_mcp_server.py"), str(executed)],
                cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

            def send(msg):
                proc.stdin.write((json.dumps(msg) + "\n").encode())
                proc.stdin.flush()

            try:
                send({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "delete_file", "arguments": {"path": "old.txt"}}})
                for _ in range(200):
                    if list_pending(tmp):
                        break
                    time.sleep(0.05)
                self.assertEqual(len(list_pending(tmp)), 1)

                # While the call waits for a human, other requests still get answered.
                send({"jsonrpc": "2.0", "id": 2, "method": "ping"})
                self.assertEqual(json.loads(proc.stdout.readline())["id"], 2)
                self.assertFalse(executed.exists())

                decide(list_pending(tmp)[0]["id"], True, tmp)
                reply = json.loads(proc.stdout.readline())
                self.assertEqual(reply["id"], 1)
                self.assertNotIn("isError", reply["result"])
                self.assertTrue(executed.exists())
                entry = AuditLog(tmp / "audit.jsonl").read()[-1]
                self.assertTrue(entry["approved_by_human"])
            finally:
                proc.stdin.close()
                proc.wait(timeout=10)
                proc.stdout.close()


if __name__ == "__main__":
    unittest.main()
