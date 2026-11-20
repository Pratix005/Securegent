import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from securegent import Policy  # noqa: E402
from securegent.redteam import BLOCKED, COMPROMISED, RESISTED, SCENARIOS, run_policy  # noqa: E402
from securegent.redteam.community import ScenarioError, load_scenarios, scenario_from_dict  # noqa: E402

ATTACKS = ROOT / "attacks"


class CommunityScenarioTests(unittest.TestCase):
    def test_every_contributed_attack_is_valid_real_and_stopped(self):
        scenarios = load_scenarios(ATTACKS)
        self.assertGreaterEqual(len(scenarios), 2)
        builtin_ids = {s.id for s in SCENARIOS}
        policy = Policy.from_file(ROOT / "policies.json")
        for s in scenarios:
            with self.subTest(s.id):
                self.assertNotIn(s.id, builtin_ids)
                self.assertEqual(run_policy(s, None).outcome, COMPROMISED, "must work without a guard")
                self.assertIn(run_policy(s, policy).outcome, (BLOCKED, RESISTED), "policies.json must stop it")

    def test_known_bypasses_still_get_through(self):
        """Documented limitations (docs/design.md#known-bypasses). If one starts failing here,
        it has been fixed: move it to attacks/ and update the docs."""
        policy = Policy.from_file(ROOT / "policies.json")
        bypasses = load_scenarios(ATTACKS / "known-bypasses")
        self.assertEqual(len(bypasses), 2)
        for s in bypasses:
            with self.subTest(s.id):
                self.assertEqual(run_policy(s, policy).outcome, COMPROMISED)

    def test_template_is_valid_and_skipped_in_folders(self):
        data = json.loads((ATTACKS / "TEMPLATE.json").read_text(encoding="utf-8"))
        scenario_from_dict(data)
        self.assertNotIn("my-attack-name", {s.id for s in load_scenarios(ATTACKS)})

    def test_custom_harm_conditions(self):
        s = scenario_from_dict({
            "id": "x", "name": "x", "category": "c", "description": "d",
            "attack_calls": [["email.send", {"to": "a@acme.com", "subject": "s", "body": "b",
                                             "attachment": "customers.csv"}]],
            "harm": [{"tool": "email.send", "when": [{"arg": "attachment", "op": "equals", "value": "customers.csv"}]}]})
        self.assertTrue(s.harm("email.send", {"attachment": "customers.csv"}))
        self.assertFalse(s.harm("email.send", {"attachment": None}))
        self.assertFalse(s.harm("files.read", {"attachment": "customers.csv"}))

    def test_bad_files_are_explained(self):
        base = {"id": "x", "name": "x", "category": "c", "description": "d",
                "attack_calls": [["payments.pay", {"vendor": "X", "amount": 1}]],
                "harm": [{"builtin": "pays_unapproved"}]}
        cases = [({"id": "Bad Id"}, "id must be"),
                 ({"attack_calls": [["shell.run", {}]]}, "unknown tool"),
                 ({"harm": [{"builtin": "nope"}]}, "unknown builtin"),
                 ({"harm": [{"tool": "email.send", "when": [{"arg": "to", "op": "sounds_like", "value": 1}]}]}, "bad 'harm'"),
                 ({"harm": [{"builtin": "deletes_files"}]}, "could never be COMPROMISED"),
                 ({"name": ""}, "'name' is required")]
        for change, message in cases:
            with self.subTest(message), self.assertRaises(ScenarioError) as ctx:
                scenario_from_dict({**base, **change})
            self.assertIn(message, str(ctx.exception))

    def test_cli_runs_and_rejects_duplicate_ids(self):
        out = subprocess.run([sys.executable, "-m", "securegent.redteam", "--scenarios", str(ATTACKS)],
                             cwd=ROOT, capture_output=True, text=True, timeout=120)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn(f"/{len(SCENARIOS) + len(load_scenarios(ATTACKS))}", out.stdout)
        with tempfile.TemporaryDirectory() as tmp:
            dup = json.loads((ATTACKS / "TEMPLATE.json").read_text(encoding="utf-8"))
            dup["id"] = "fake-cfo-wire"                       # a built-in id
            (Path(tmp) / "dup.json").write_text(json.dumps(dup), encoding="utf-8")
            out = subprocess.run([sys.executable, "-m", "securegent.redteam", "--scenarios", tmp],
                                 cwd=ROOT, capture_output=True, text=True, timeout=60)
            self.assertEqual(out.returncode, 2)
            self.assertIn("already used", out.stderr)


if __name__ == "__main__":
    unittest.main()
