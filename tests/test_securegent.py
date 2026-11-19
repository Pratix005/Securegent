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


class PolicyFeatureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.reg = AgentRegistry(secret=b"s")
        self.reg.register("bot", owner="alice", allowed_scopes=["*"])

    def tearDown(self):
        self.tmp.cleanup()

    def _guard(self, rules, approvals=None):
        approvals = approvals or []
        g = Guard(self.reg, Policy(rules), AuditLog(Path(self.tmp.name) / "a.jsonl"),
                  approver=lambda r: approvals.pop(0) if approvals else False)
        g.tool("send")(lambda to: "sent")
        g.tool("pay")(lambda vendor, amount: "paid")
        return g, self.reg.issue_token("bot", ["send", "pay"])

    def test_matches_blocks_smuggled_recipient(self):
        g, t = self._guard([{"id": "internal", "tool": "send", "effect": "allow",
                             "when": [{"arg": "to", "op": "matches", "value": r"[a-z0-9._%+-]+@acme\.com"}]}])
        self.assertEqual(g.call(t, "send", to="Finance@acme.com"), "sent")
        for bad in ["x@evil.ru, finance@acme.com", "finance@acme.com.evil.ru", "a@acme.com;b@evil.ru"]:
            with self.assertRaises(Blocked, msg=bad):
                g.call(t, "send", to=bad)

    def test_bad_regex_rejected_at_load(self):
        with self.assertRaises(ValueError):
            Policy([{"id": "x", "tool": "send", "effect": "allow",
                     "when": [{"arg": "to", "op": "matches", "value": "("}]}])

    def test_running_limit_escalates_to_approval(self):
        rules = [{"id": "small", "tool": "pay", "effect": "allow",
                  "when": [{"arg": "amount", "op": "lte", "value": 100}],
                  "limit": {"sum_arg": "amount", "max": 100, "window_seconds": 3600}}]
        g, t = self._guard(rules)
        g.call(t, "pay", vendor="v", amount=60)
        with self.assertRaises(Blocked) as ctx:            # 60 + 60 > 100 -> needs approval (refused)
            g.call(t, "pay", vendor="v", amount=60)
        self.assertIn("limit exceeded", str(ctx.exception))
        g.call(t, "pay", vendor="v", amount=40)            # 60 + 40 = 100 is still allowed

    def test_running_limit_allows_when_human_approves(self):
        rules = [{"id": "small", "tool": "pay", "effect": "allow",
                  "limit": {"sum_arg": "amount", "max": 100, "window_seconds": 3600}}]
        g, t = self._guard(rules, approvals=[True])
        g.call(t, "pay", vendor="v", amount=90)
        self.assertEqual(g.call(t, "pay", vendor="v", amount=90), "paid")

    def test_limit_only_on_allow_rules(self):
        with self.assertRaises(ValueError):
            Policy([{"id": "x", "tool": "pay", "effect": "deny",
                     "limit": {"max": 1, "window_seconds": 1}}])


class RedTeamTests(unittest.TestCase):
    POLICY = Path(__file__).resolve().parent.parent / "policies.json"

    def test_sample_policy_stops_every_attack_and_allows_normal_work(self):
        from securegent.redteam import COMPROMISED, SCENARIOS, run_policy, score
        from securegent.redteam.runner import check_normal_work
        policy = Policy.from_file(self.POLICY)
        self.assertEqual(check_normal_work(policy), [])
        results = [run_policy(s, policy) for s in SCENARIOS]
        failed = [r.scenario.id for r in results if r.outcome == COMPROMISED]
        self.assertEqual(failed, [])
        safe, total, grade = score(results)
        self.assertEqual((safe, total, grade), (len(SCENARIOS), len(SCENARIOS), "A"))

    def test_no_guard_baseline_is_compromised_by_every_attack(self):
        from securegent.redteam import COMPROMISED, SCENARIOS, run_policy
        results = [run_policy(s, None) for s in SCENARIOS]
        self.assertTrue(all(r.outcome == COMPROMISED for r in results))


if __name__ == "__main__":
    unittest.main()
