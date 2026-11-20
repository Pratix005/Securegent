import json
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from securegent import approvals
from securegent.approvals import FileApprover
from securegent.slack import SlackApproval

BOSS, OTHER = "UBOSS", "URANDOM"
REQUEST = {"agent": "finance-assistant", "on_behalf_of": "priya@acme.com", "tool": "payments.pay",
           "args": {"vendor": "Unknown Ltd", "amount": 250000}, "reason": "large payment"}


class FakeSlack:
    """Just enough of the Slack Web API: postMessage, reactions.get, update."""

    def __init__(self):
        self.posted, self.updated, self.reactions = [], [], []
        self.fail_auth = False
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _reply(self, body):
                data = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if fake.fail_auth or self.headers.get("Authorization") != "Bearer xoxb-test":
                    return self._reply({"ok": False, "error": "invalid_auth"})
                if self.path.endswith("chat.postMessage"):
                    fake.posted.append(body)
                    return self._reply({"ok": True, "channel": body["channel"], "ts": "1700000000.000100"})
                if self.path.endswith("chat.update"):
                    fake.updated.append(body)
                    return self._reply({"ok": True})
                self._reply({"ok": False, "error": "unknown_method"})

            def do_GET(self):
                url = urlparse(self.path)
                q = parse_qs(url.query)
                assert q["timestamp"] == ["1700000000.000100"]
                self._reply({"ok": True, "message": {"reactions": fake.reactions}})

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}/api"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class SlackApprovalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.slack = FakeSlack()
        self.channel = SlackApproval("xoxb-test", "CAPPROVE", [BOSS], api_base=self.slack.base)
        self.channel.poll_interval = 0.05
        self.approver = FileApprover(self.tmp.name, timeout=1.5, poll=0.02, channels=[self.channel])

    def tearDown(self):
        self.slack.stop()
        self.tmp.cleanup()

    def react_soon(self, *reactions, delay=0.2):
        def go():
            time.sleep(delay)
            self.slack.reactions = list(reactions)
        threading.Thread(target=go, daemon=True).start()

    def test_listed_approver_approves(self):
        self.react_soon({"name": "white_check_mark", "users": [BOSS]})
        self.assertTrue(self.approver(REQUEST))
        post = self.slack.posted[0]
        self.assertEqual(post["channel"], "CAPPROVE")
        self.assertIn("payments.pay", post["text"])
        self.assertIn("250000", post["text"])
        self.assertIn(f"<@{BOSS}>", post["text"])
        self.assertIn("Approved", self.slack.updated[-1]["text"])
        self.assertIn(f"by <@{BOSS}>", self.slack.updated[-1]["text"])
        self.assertEqual(approvals.list_pending(self.tmp.name), [])

    def test_reactions_from_others_are_ignored(self):
        self.react_soon({"name": "white_check_mark", "users": [OTHER]})
        self.assertFalse(self.approver(REQUEST))
        self.assertIn("Expired", self.slack.updated[-1]["text"])

    def test_deny_wins_and_skin_tones_count(self):
        self.react_soon({"name": "+1::skin-tone-3", "users": [BOSS]}, {"name": "x", "users": [BOSS]})
        self.assertFalse(self.approver(REQUEST))
        self.assertIn("Denied", self.slack.updated[-1]["text"])

    def test_dashboard_answer_first_updates_slack(self):
        def answer():
            for _ in range(50):
                pending = approvals.list_pending(self.tmp.name)
                if pending:
                    approvals.decide(pending[0]["id"], True, self.tmp.name)
                    return
                time.sleep(0.02)
        threading.Thread(target=answer, daemon=True).start()
        self.assertTrue(self.approver(REQUEST))
        self.assertIn("in the dashboard", self.slack.updated[-1]["text"])

    def test_slack_down_falls_back_to_dashboard(self):
        self.slack.fail_auth = True
        def answer():
            for _ in range(50):
                pending = approvals.list_pending(self.tmp.name)
                if pending:
                    approvals.decide(pending[0]["id"], False, self.tmp.name)
                    return
                time.sleep(0.02)
        threading.Thread(target=answer, daemon=True).start()
        self.assertFalse(self.approver(REQUEST))
        self.assertEqual(self.slack.posted, [])

    def test_configuration_is_checked(self):
        with self.assertRaises(ValueError):
            SlackApproval("xoxb", "C1", [])              # nobody may approve -> refuse
        with self.assertRaises(ValueError):
            SlackApproval("", "C1", ["U1"])
        with self.assertRaises(ValueError):
            SlackApproval("xoxb", "", ["U1"])


if __name__ == "__main__":
    unittest.main()
