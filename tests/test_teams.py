import json
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from securegent import approvals  # noqa: E402
from securegent.approvals import FileApprover  # noqa: E402
from securegent.teams import TeamsApproval, TeamsAuth, TeamsError  # noqa: E402

BOSS_ID, OTHER_ID = "11111111-aaaa", "22222222-bbbb"
REQUEST = {"agent": "finance-assistant", "on_behalf_of": "priya@acme.com", "tool": "payments.pay",
           "args": {"vendor": "Unknown <b>Ltd</b>", "amount": 250000}, "reason": "large payment"}


class FakeMicrosoft:
    """Device-code login, token refresh and the bits of Graph that Teams approvals use."""

    def __init__(self):
        self.posts, self.reactions, self.token_calls = [], [], []
        self.pending_polls = 2            # device code: "authorization_pending" this many times
        self.graph_down = False
        self.refresh_seen = []
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def reply(self, status, body):
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def body(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
                return parse_qs(raw) if "urlencoded" in self.headers.get("Content-Type", "") else json.loads(raw or "{}")

            def authed(self):
                if self.headers.get("Authorization", "").startswith("Bearer access-"):
                    return True
                self.reply(401, {"error": {"code": "InvalidAuthenticationToken", "message": "bad token"}})
                return False

            def do_POST(self):
                path, b = urlparse(self.path).path, self.body()
                if path.endswith("/devicecode"):
                    return self.reply(200, {"device_code": "DC", "user_code": "ABCD-1234", "interval": 0,
                                            "expires_in": 60, "verification_uri": "https://microsoft.com/devicelogin",
                                            "message": "Go to https://microsoft.com/devicelogin and enter ABCD-1234"})
                if path.endswith("/token"):
                    fake.token_calls.append(b["grant_type"][0])
                    if b["grant_type"][0].endswith("device_code"):
                        if fake.pending_polls > 0:
                            fake.pending_polls -= 1
                            return self.reply(400, {"error": "authorization_pending",
                                                    "error_description": "AADSTS70016: pending"})
                        return self.reply(200, {"access_token": "access-1", "refresh_token": "refresh-1", "expires_in": 3600})
                    fake.refresh_seen.append(b["refresh_token"][0])
                    n = len(fake.refresh_seen) + 1
                    return self.reply(200, {"access_token": f"access-{n}", "refresh_token": f"refresh-{n}", "expires_in": 3600})
                if not self.authed():
                    return
                if fake.graph_down:
                    return self.reply(503, {"error": {"code": "ServiceUnavailable", "message": "down"}})
                fake.posts.append((unquote(path), b))
                self.reply(201, {"id": f"msg-{len(fake.posts)}"})

            def do_GET(self):
                if not self.authed():
                    return
                path = unquote(urlparse(self.path).path)
                if "/users/" in path:
                    return self.reply(200, {"id": BOSS_ID, "displayName": "Boss Person"})
                self.reply(200, {"id": path.rsplit("/", 1)[-1], "reactions": fake.reactions})

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def reaction(kind, user_id):
    return {"reactionType": kind, "user": {"user": {"id": user_id}}}


class TeamsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ms = FakeMicrosoft()
        self.auth = TeamsAuth(Path(self.tmp.name) / "teams-token.json", login_base=self.ms.base)
        self.auth.login("tenant-1", "client-1", out=lambda m: None)

    def tearDown(self):
        self.ms.stop()
        self.tmp.cleanup()

    def channel(self, target="chat:19:abc@thread.v2", approvers=("boss@college.edu",)):
        ch = TeamsApproval(self.auth, target, list(approvers), api_base=self.ms.base + "/v1.0")
        ch.poll_interval = 0.05
        return ch

    def approver(self, *channels, timeout=1.5):
        return FileApprover(self.tmp.name, timeout=timeout, poll=0.02, channels=list(channels))

    def react_soon(self, *reactions):
        threading.Thread(target=lambda: (time.sleep(0.2), setattr(self.ms, "reactions", list(reactions))),
                         daemon=True).start()

    def test_device_login_waits_then_saves_token_and_refresh_rotates(self):
        self.assertEqual(self.ms.token_calls.count("urn:ietf:params:oauth:grant-type:device_code"), 3)
        saved = json.loads((Path(self.tmp.name) / "teams-token.json").read_text())
        self.assertEqual(saved["refresh_token"], "refresh-1")
        fresh = TeamsAuth(Path(self.tmp.name) / "teams-token.json", login_base=self.ms.base)
        self.assertEqual(fresh.token(), "access-2")
        self.assertEqual(json.loads((Path(self.tmp.name) / "teams-token.json").read_text())["refresh_token"], "refresh-2")

    def test_listed_approver_approves_in_a_chat(self):
        self.react_soon(reaction("like", BOSS_ID))
        self.assertTrue(self.approver(self.channel())(REQUEST))
        path, first = self.ms.posts[0]
        self.assertEqual(path, "/v1.0/chats/19:abc@thread.v2/messages")
        self.assertIn("payments.pay", first["body"]["content"])
        self.assertIn("Unknown &lt;b&gt;Ltd&lt;/b&gt;", first["body"]["content"])   # HTML escaped
        self.assertIn("Boss Person", first["body"]["content"])
        self.assertIn("Approved by Boss Person", self.ms.posts[-1][1]["body"]["content"])

    def test_others_ignored_and_deny_wins(self):
        self.react_soon(reaction("like", OTHER_ID))
        self.assertFalse(self.approver(self.channel())(REQUEST))
        self.assertIn("Expired", self.ms.posts[-1][1]["body"]["content"])
        self.ms.reactions = []
        self.react_soon(reaction("like", BOSS_ID), reaction("👎", BOSS_ID))
        self.assertFalse(self.approver(self.channel())(REQUEST))
        self.assertIn("Denied by Boss Person", self.ms.posts[-1][1]["body"]["content"])

    def test_channel_outcome_is_a_thread_reply(self):
        self.react_soon(reaction("✅", BOSS_ID))
        self.assertTrue(self.approver(self.channel("channel:team-1/19:chan@thread.tacv2"))(REQUEST))
        self.assertEqual(self.ms.posts[0][0], "/v1.0/teams/team-1/channels/19:chan@thread.tacv2/messages")
        self.assertEqual(self.ms.posts[-1][0], "/v1.0/teams/team-1/channels/19:chan@thread.tacv2/messages/msg-1/replies")

    def test_graph_down_falls_back_to_dashboard(self):
        self.ms.graph_down = True
        def answer():
            for _ in range(50):
                p = approvals.list_pending(self.tmp.name)
                if p:
                    return approvals.decide(p[0]["id"], True, self.tmp.name)
                time.sleep(0.02)
        threading.Thread(target=answer, daemon=True).start()
        self.assertTrue(self.approver(self.channel())(REQUEST))

    def test_two_channels_first_answer_wins_and_the_other_is_told(self):
        a, b = self.channel(), self.channel("channel:team-1/chan")
        self.react_soon(reaction("like", BOSS_ID))          # both see the reaction; first poll wins
        self.assertTrue(self.approver(a, b)(REQUEST))
        outcomes = [p[1]["body"]["content"] for p in self.ms.posts if "request" in p[1]["body"]["content"]
                    and "Approved" in p[1]["body"]["content"]]
        self.assertTrue(any("by Boss Person" in o for o in outcomes))
        self.assertTrue(any("in another app" in o for o in outcomes))

    def test_configuration_checked(self):
        with self.assertRaises(ValueError):
            self.channel("teams:nope")
        with self.assertRaises(ValueError):
            self.channel(approvers=())
        with self.assertRaises(TeamsError):
            TeamsAuth(Path(self.tmp.name) / "missing.json").token()


if __name__ == "__main__":
    unittest.main()
