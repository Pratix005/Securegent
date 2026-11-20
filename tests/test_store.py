import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from securegent import AgentRegistry, AuditLog, Blocked, Guard, Policy
from securegent.store import MemoryUsage, SqliteUsage

RULES = [{"id": "pay", "tool": "pay", "effect": "allow",
          "limit": {"sum_arg": "amount", "max": 100, "window_seconds": 3600}}]

WORKER = r"""
import sys
sys.path.insert(0, sys.argv[2])
from securegent.store import SqliteUsage
store = SqliteUsage(sys.argv[1])
ok = sum(store.reserve("bot", "r", 1, 3600, 30)[0] for _ in range(20))
print(ok)
"""


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "usage.db"
        self.stores = []

    def tearDown(self):
        for s in self.stores:
            s.close()
        self.tmp.cleanup()

    def sqlite(self):
        s = SqliteUsage(self.db)
        self.stores.append(s)
        return s

    def guard(self, usage):
        reg = AgentRegistry(secret=b"k")
        reg.register("bot", owner="alice", allowed_scopes=["pay"])
        g = Guard(reg, Policy(RULES), AuditLog(Path(self.tmp.name) / "audit.jsonl"), usage=usage)
        g.tool("pay")(lambda amount: "paid")
        return g, reg.issue_token("bot", ["pay"])

    def test_limits_survive_a_restart_with_sqlite(self):
        g, t = self.guard(self.sqlite())
        g.call(t, "pay", amount=80)
        g2, t2 = self.guard(self.sqlite())          # "restarted" process
        with self.assertRaises(Blocked):
            g2.call(t2, "pay", amount=30)
        self.assertEqual(g2.call(t2, "pay", amount=20), "paid")

    def test_memory_usage_resets_on_restart(self):
        g, t = self.guard(MemoryUsage())
        g.call(t, "pay", amount=80)
        g2, t2 = self.guard(MemoryUsage())
        self.assertEqual(g2.call(t2, "pay", amount=30), "paid")

    def test_negative_or_nan_amounts_cannot_make_room(self):
        for usage in (MemoryUsage(), self.sqlite()):
            g, t = self.guard(usage)
            g.call(t, "pay", amount=90)
            for bad in (-1000, float("nan"), "lots"):
                with self.assertRaises(Blocked):
                    g.call(t, "pay", amount=bad)
            self.assertEqual(g.call(t, "pay", amount=10), "paid")

    def test_processes_share_one_limit_atomically(self):
        self.sqlite()                                         # create the schema first
        procs = [subprocess.Popen([sys.executable, "-c", WORKER, str(self.db), str(ROOT)],
                                  stdout=subprocess.PIPE, text=True) for _ in range(4)]
        granted = sum(int(p.communicate(timeout=60)[0]) for p in procs)
        self.assertEqual(granted, 30)                         # 80 attempts, limit 30
        ok, total = self.sqlite().reserve("bot", "r", 0, 3600, 30)
        self.assertEqual(total, 30)


if __name__ == "__main__":
    unittest.main()


PG_DSN = os.environ.get("SECUREGENT_TEST_POSTGRES")
PG_WORKER = r"""
import sys
sys.path.insert(0, sys.argv[2])
from securegent.store import PostgresUsage
store = PostgresUsage(sys.argv[1], table="sg_test_usage")
print(sum(store.reserve("bot", "r", 1, 3600, 30)[0] for _ in range(20)))
"""


@unittest.skipUnless(PG_DSN, "set SECUREGENT_TEST_POSTGRES=postgresql://... to run")
class PostgresStoreTests(unittest.TestCase):
    def setUp(self):
        from securegent.store import PostgresUsage
        self.make = lambda: PostgresUsage(PG_DSN, table="sg_test_usage")
        self.stores = [self.make()]
        self.stores[0]._connect().execute("TRUNCATE sg_test_usage")
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        for s in self.stores:
            s.close()
        self.tmp.cleanup()

    def guard(self, usage):
        reg = AgentRegistry(secret=b"k")
        reg.register("bot", owner="alice", allowed_scopes=["pay"])
        g = Guard(reg, Policy(RULES), AuditLog(Path(self.tmp.name) / "audit.jsonl"), usage=usage)
        g.tool("pay")(lambda amount: "paid")
        return g, reg.issue_token("bot", ["pay"])

    def test_limits_survive_a_restart(self):
        g, t = self.guard(self.stores[0])
        g.call(t, "pay", amount=80)
        self.stores.append(self.make())
        g2, t2 = self.guard(self.stores[-1])
        with self.assertRaises(Blocked):
            g2.call(t2, "pay", amount=30)
        self.assertEqual(g2.call(t2, "pay", amount=20), "paid")

    def test_bad_amounts_and_human_approved_use(self):
        s = self.stores[0]
        self.assertFalse(s.reserve("bot", "r", float("inf"), 3600, 100)[0])
        s.add("bot", "r", 90)                      # approved over the limit, still counts
        self.assertEqual(s.reserve("bot", "r", 20, 3600, 100), (False, 110.0))

    def test_processes_share_one_limit_atomically(self):
        procs = [subprocess.Popen([sys.executable, "-c", PG_WORKER, PG_DSN, str(ROOT)],
                                  stdout=subprocess.PIPE, text=True) for _ in range(4)]
        self.assertEqual(sum(int(p.communicate(timeout=120)[0]) for p in procs), 30)

    def test_bad_table_name_rejected(self):
        from securegent.store import PostgresUsage
        with self.assertRaises(ValueError):
            PostgresUsage(PG_DSN, table="x; DROP TABLE y")
