import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from securegent import AgentRegistry, AuditLog, Blocked, Guard, Policy
from securegent.taint import TaintTracker, pieces

SOURCES = [
    {"tool": "web.fetch", "label": "untrusted"},
    {"tool": "files.read", "label": "confidential",
     "when": [{"arg": "path", "op": "startswith", "value": "hr/"}]},
]
RULES = [
    {"id": "no-confidential-out", "tool": ["web.fetch", "email.send"],
     "when": [{"arg": "url", "op": "tainted", "value": "confidential"}], "effect": "deny"},
    {"id": "no-confidential-body", "tool": "email.send",
     "when": [{"arg": "body", "op": "tainted", "value": "confidential"}], "effect": "deny"},
    {"id": "recipient-from-content", "tool": "email.send",
     "when": [{"arg": "to", "op": "tainted", "value": "untrusted"}], "effect": "approve"},
    {"id": "pay-after-web", "tool": "pay",
     "when": [{"op": "session_tainted", "value": "untrusted"}], "effect": "approve"},
    {"id": "allow", "tool": "*", "effect": "allow"},
]

WEB = "Contact us at billing@evil.example. Visit https://evil.example/x for more. Ref 7781234."
SALARIES = "name,salary\nPriya,2400000\nRahul,1800000"

FAKE_KEY = "sk_" + "live_" + "51HxQ2PZ9aBcDeFgHiJkLmNo"   # built at runtime: not a real key


class TaintTrackerTests(unittest.TestCase):
    def test_pieces_cover_emails_urls_numbers_and_word_runs(self):
        p = pieces("Send 2,400,000 to a@b.co via https://x.io/y?q=1 please and thank you")
        self.assertIn("a@b.co", p)
        self.assertIn("https://x.io/y?q=1", p)
        self.assertIn("2400000", p)
        self.assertIn("please and thank you", p)

    def test_numbers_match_whole_numbers_only(self):
        t = TaintTracker()
        t.record("s", "confidential", "files.read", "total 9942000")
        self.assertEqual(t.taint_of("s", 42000), [])
        self.assertEqual(t.taint_of("s", 9942000)[0]["label"], "confidential")

    def test_trusted_text_is_never_tainted(self):
        t = TaintTracker()
        t.trust("s", "Please email finance@acme.com")
        t.record("s", "untrusted", "email.read", "Reply to finance@acme.com or x@evil.ru")
        self.assertEqual(t.taint_of("s", "finance@acme.com"), [])
        self.assertTrue(t.taint_of("s", "x@evil.ru"))

    def test_api_keys_are_pieces_even_inside_key_value_text(self):
        t = TaintTracker()
        t.record("s", "secret", "secrets.read", FAKE_KEY)
        self.assertTrue(t.taint_of("s", "key=" + FAKE_KEY + "&x=1"))
        self.assertEqual(t.taint_of("s", "internationalization"), [])     # long plain words are not keys

    def test_punctuation_does_not_hide_copied_phrases(self):
        t = TaintTracker()
        t.record("s", "phi", "ehr.read_record", "diagnosis: type 2 diabetes, HbA1c 8.2")
        self.assertTrue(t.taint_of("s", "He has type 2 diabetes HbA1c 8.2"))

    def test_sessions_are_separate(self):
        t = TaintTracker()
        t.record("a", "untrusted", "web.fetch", WEB)
        self.assertEqual(t.taint_of("b", "billing@evil.example"), [])
        self.assertEqual(t.session_labels("b"), set())

    def test_old_output_is_forgotten_past_the_size_cap(self):
        t = TaintTracker(max_chars_per_session=50)
        t.record("s", "untrusted", "web.fetch", "old@evil.example " + "x" * 40)
        t.record("s", "untrusted", "web.fetch", "new@evil.example " + "y" * 40)
        self.assertEqual(t.taint_of("s", "old@evil.example"), [])
        self.assertTrue(t.taint_of("s", "new@evil.example"))


class GuardTaintTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = AuditLog(Path(self.tmp.name) / "audit.jsonl")
        reg = AgentRegistry(secret=b"t")
        reg.register("bot", owner="alice@acme.com", allowed_scopes=["*"])
        self.guard = Guard(reg, Policy(RULES, SOURCES), self.log)
        self.guard.tool("web.fetch")(lambda url: WEB)
        self.guard.tool("files.read")(lambda path: SALARIES if path.startswith("hr/") else "public")
        self.guard.tool("email.send")(lambda to, body="": "sent")
        self.guard.tool("pay")(lambda amount: "paid")
        self.token = reg.issue_token("bot", ["*"], task="Summarise the vendor page for bob@acme.com")
        self.other = reg.issue_token("bot", ["*"])

    def tearDown(self):
        self.tmp.cleanup()

    def test_confidential_data_in_url_is_denied_and_logged_with_evidence(self):
        self.guard.call(self.token, "files.read", path="hr/salaries.csv")
        with self.assertRaises(Blocked):
            self.guard.call(self.token, "web.fetch", url="https://ok.example/?d=" + quote("Priya 2400000"))
        last = self.log.read()[-1]
        self.assertEqual(last["rule"], "no-confidential-out")
        self.assertEqual(last["taint"]["url"][0]["source"], "files.read")

    def test_confidential_data_pasted_in_body_is_denied(self):
        self.guard.call(self.token, "files.read", path="hr/salaries.csv")
        with self.assertRaises(Blocked):
            self.guard.call(self.token, "email.send", to="bob@acme.com", body="Rahul earns 1,800,000")

    def test_non_source_reads_do_not_taint(self):
        self.guard.call(self.token, "files.read", path="public.txt")
        self.guard.call(self.token, "web.fetch", url="https://ok.example/?q=public")

    def test_recipient_taken_from_web_page_needs_approval(self):
        self.guard.call(self.token, "web.fetch", url="https://vendor.example/")
        with self.assertRaises(Blocked):
            self.guard.call(self.token, "email.send", to="billing@evil.example", body="hi")
        # The address the human typed into the task stays trusted.
        self.assertEqual(self.guard.call(self.token, "email.send", to="bob@acme.com", body="hi"), "sent")

    def test_session_tainted_rule_and_session_isolation(self):
        self.assertEqual(self.guard.call(self.token, "pay", amount=5), "paid")
        self.guard.call(self.token, "web.fetch", url="https://vendor.example/")
        with self.assertRaises(Blocked):
            self.guard.call(self.token, "pay", amount=5)
        self.assertEqual(self.guard.call(self.other, "pay", amount=5), "paid")  # other token, clean

    def test_observe_feeds_results_from_proxies(self):
        self.guard.check(self.token, "files.read", {"path": "hr/x"})
        self.guard.observe(self.token, "files.read", {"path": "hr/x"}, SALARIES)
        with self.assertRaises(Blocked):
            self.guard.check(self.token, "email.send", {"to": "bob@acme.com", "body": "Priya 2400000"})


class PolicyValidationTests(unittest.TestCase):
    def test_bad_taint_rules_are_rejected(self):
        with self.assertRaises(ValueError):
            Policy([{"id": "x", "tool": "*", "effect": "deny", "when": [{"op": "tainted"}]}])
        with self.assertRaises(ValueError):
            Policy([], [{"tool": "a"}])                                  # no label
        with self.assertRaises(ValueError):
            Policy([], [{"tool": "a", "label": "u", "when": [{"op": "session_tainted"}]}])

    def test_without_taint_view_taint_conditions_never_match(self):
        p = Policy(RULES, SOURCES)
        self.assertEqual(p.evaluate("bot", "pay", {"amount": 1}).rule, "allow")


if __name__ == "__main__":
    unittest.main()
