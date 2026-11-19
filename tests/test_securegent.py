import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from securegent import AgentRegistry, AuditLog, AuthError, Blocked, Guard, Policy

RULES = [
    {"id": "small-pay", "tool": "pay", "when": [{"arg": "amount", "op": "lte", "value": 100}], "effect": "allow"},
    {"id": "big-pay", "tool": "pay", "effect": "approve", "reason": "big"},
    {"id": "read", "tool": "read", "effect": "allow"},
]


class SecuregentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = AuditLog(Path(self.tmp.name) / "audit.jsonl")
        self.reg = AgentRegistry(secret=b"test-secret")
        self.reg.register("bot", owner="alice", allowed_scopes=["pay", "read"])
        self.approvals = []
        self.guard = Guard(self.reg, Policy(RULES), self.log,
                           approver=lambda r: self.approvals.pop(0) if self.approvals else False)
        self.guard.tool("pay")(lambda amount: f"paid {amount}")
        self.guard.tool("read")(lambda path: "data")
        self.guard.tool("delete")(lambda path: "gone")
        self.token = self.reg.issue_token("bot", ["pay", "read"])

    def tearDown(self):
        self.tmp.cleanup()

    def test_allowed_call_runs_and_is_logged(self):
        self.assertEqual(self.guard.call(self.token, "pay", amount=50), "paid 50")
        self.assertEqual(self.log.read()[-1]["decision"], "allow")

    def test_approval_required(self):
        with self.assertRaises(Blocked):
            self.guard.call(self.token, "pay", amount=500)
        self.approvals.append(True)
        self.assertEqual(self.guard.call(self.token, "pay", amount=500), "paid 500")
        self.assertTrue(self.log.read()[-1]["approved_by_human"])

    def test_tool_outside_token_scope_blocked(self):
        with self.assertRaises(Blocked):
            self.guard.call(self.token, "delete", path="x")

    def test_cannot_issue_scope_beyond_agent_limit(self):
        with self.assertRaises(AuthError):
            self.reg.issue_token("bot", ["delete"])

    def test_default_deny_when_no_rule_matches(self):
        token = self.reg.issue_token("bot", ["read", "pay"])
        self.guard.policy = Policy([])
        with self.assertRaises(Blocked):
            self.guard.call(token, "read", path="x")

    def test_tampered_token_rejected(self):
        body, sig = self.token.split(".")
        with self.assertRaises(Blocked):
            self.guard.call(body + "x." + sig, "read", path="x")

    def test_expired_token_rejected(self):
        token = self.reg.issue_token("bot", ["read"], ttl_seconds=-1)
        with self.assertRaises(Blocked):
            self.guard.call(token, "read", path="x")

    def test_revoked_token_rejected(self):
        self.reg.revoke_token(self.token)
        with self.assertRaises(Blocked):
            self.guard.call(self.token, "read", path="x")

    def test_kill_switch(self):
        self.reg.disable("bot")
        with self.assertRaises(Blocked):
            self.guard.call(self.token, "read", path="x")
        with self.assertRaises(AuthError):
            self.reg.issue_token("bot", ["read"])


if __name__ == "__main__":
    unittest.main()
