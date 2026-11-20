"""
Where running limits ("max Rs 1 lakh per day", "max 50 writes per hour") keep their totals.

  MemoryUsage  totals live in the process; a restart starts from zero. Fine for tests,
               demos and short scripts.
  SqliteUsage  totals live in a SQLite file. They survive restarts and crashes (so killing
               the agent's process can't reset a daily limit), and several processes, such
               as one MCP proxy per server, can share one limit safely.
  PostgresUsage  totals live in PostgreSQL, shared by proxies on several machines.

All offer reserve(): check the total and record the new use in one atomic step, so two
calls arriving at the same moment can't both squeeze under the limit.
"""

import math
import sqlite3
import threading
import time
from pathlib import Path

KEEP_SECONDS = 40 * 24 * 3600      # usage older than this is never needed by a sane window


class MemoryUsage:
    def close(self) -> None:
        pass

    def __init__(self):
        self._rows: list[tuple[float, str, str, float]] = []    # (time, agent, rule, value)
        self._lock = threading.Lock()

    def reserve(self, agent: str, rule: str, value: float, window: float, maximum: float) -> tuple[bool, float]:
        """Record `value` if the total in the window stays <= maximum.
        Returns (recorded, total including this value)."""
        now = time.time()
        with self._lock:
            used = sum(v for t, a, r, v in self._rows if t >= now - window and a == agent and r == rule)
            total = used + value
            if total > maximum:
                return False, total
            self._rows.append((now, agent, rule, value))
            return True, total

    def add(self, agent: str, rule: str, value: float) -> None:
        """Record use that a human approved over the limit; it still counts."""
        with self._lock:
            self._rows.append((time.time(), agent, rule, value))


class SqliteUsage:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._all: list[sqlite3.Connection] = []     # every thread's connection, for close()
        self._all_lock = threading.Lock()
        with self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE IF NOT EXISTS usage (ts REAL NOT NULL, agent TEXT NOT NULL, "
                       "rule TEXT NOT NULL, value REAL NOT NULL)")
            db.execute("CREATE INDEX IF NOT EXISTS usage_lookup ON usage (agent, rule, ts)")
            db.execute("DELETE FROM usage WHERE ts < ?", (time.time() - KEEP_SECONDS,))

    def _connect(self) -> sqlite3.Connection:
        db = getattr(self._local, "db", None)
        if db is None:
            # isolation_level=None: we issue BEGIN IMMEDIATE ourselves, which takes the
            # write lock before reading, so check-and-record is atomic across processes.
            db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            db.execute("PRAGMA busy_timeout=30000")
            self._local.db = db
            with self._all_lock:
                self._all.append(db)
        return db

    def close(self) -> None:
        with self._all_lock:
            for db in self._all:
                try:
                    db.close()
                except sqlite3.Error:
                    pass
            self._all.clear()
        self._local = threading.local()

    def reserve(self, agent: str, rule: str, value: float, window: float, maximum: float) -> tuple[bool, float]:
        db, now = self._connect(), time.time()
        db.execute("BEGIN IMMEDIATE")
        try:
            used = db.execute("SELECT COALESCE(SUM(value), 0) FROM usage WHERE agent=? AND rule=? AND ts>=?",
                              (agent, rule, now - window)).fetchone()[0]
            total = used + value
            ok = total <= maximum and math.isfinite(value)
            if ok:
                db.execute("INSERT INTO usage VALUES (?, ?, ?, ?)", (now, agent, rule, value))
            db.execute("COMMIT")
            return ok, total
        except BaseException:
            db.execute("ROLLBACK")
            raise

    def add(self, agent: str, rule: str, value: float) -> None:
        if not math.isfinite(value):
            return
        db = self._connect()
        db.execute("BEGIN IMMEDIATE")
        db.execute("INSERT INTO usage VALUES (?, ?, ?, ?)", (time.time(), agent, rule, value))
        db.execute("COMMIT")


class PostgresUsage:
    """Totals in PostgreSQL, shared by proxies on several machines.

    Needs `pip install "securegent[postgres]"`. Keep the password out of the DSN and the
    command line: libpq reads PGPASSWORD (or ~/.pgpass) from the environment.

    Atomicity: each reserve() runs in one transaction holding a transaction-scoped advisory
    lock for that (agent, rule), so concurrent calls from any machine are serialised.
    Timestamps come from the database clock, so machines with skewed clocks still agree.
    """

    def __init__(self, dsn: str, table: str = "securegent_usage"):
        try:
            import psycopg
        except ImportError:
            raise ImportError('Postgres support needs: pip install "securegent[postgres]"') from None
        if not table.replace("_", "").isalnum() or not table[0].isalpha():
            raise ValueError("table name must be letters, digits and underscores")
        self._psycopg, self.dsn, self.table = psycopg, dsn, table
        self._local = threading.local()
        self._all: list = []
        self._all_lock = threading.Lock()
        db = self._connect()
        with db.transaction():
            # CREATE TABLE IF NOT EXISTS is not safe when several proxies start at once
            # (they collide in pg_type), so setup is serialised with an advisory lock.
            db.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (f"securegent-setup:{table}",))
            db.execute(f"CREATE TABLE IF NOT EXISTS {table} (ts DOUBLE PRECISION NOT NULL, "
                       "agent TEXT NOT NULL, rule TEXT NOT NULL, value DOUBLE PRECISION NOT NULL)")
            db.execute(f"CREATE INDEX IF NOT EXISTS {table}_lookup ON {table} (agent, rule, ts)")
            db.execute(f"DELETE FROM {table} WHERE ts < EXTRACT(EPOCH FROM clock_timestamp()) - %s",
                       (KEEP_SECONDS,))

    def _connect(self):
        db = getattr(self._local, "db", None)
        if db is None or db.closed:
            db = self._psycopg.connect(self.dsn, autocommit=True, connect_timeout=15)
            self._local.db = db
            with self._all_lock:
                self._all.append(db)
        return db

    def reserve(self, agent: str, rule: str, value: float, window: float, maximum: float) -> tuple[bool, float]:
        db = self._connect()
        with db.transaction():
            db.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (f"{agent}\x1f{rule}",))
            now, used = db.execute(
                f"SELECT EXTRACT(EPOCH FROM clock_timestamp())::float8, COALESCE(SUM(value), 0)::float8 "
                f"FROM {self.table} WHERE agent=%s AND rule=%s "
                f"AND ts >= EXTRACT(EPOCH FROM clock_timestamp()) - %s",
                (agent, rule, window)).fetchone()
            total = used + value
            ok = total <= maximum and math.isfinite(value)
            if ok:
                db.execute(f"INSERT INTO {self.table} VALUES (%s, %s, %s, %s)", (now, agent, rule, value))
        return ok, total

    def add(self, agent: str, rule: str, value: float) -> None:
        if not math.isfinite(value):
            return
        self._connect().execute(
            f"INSERT INTO {self.table} VALUES (EXTRACT(EPOCH FROM clock_timestamp()), %s, %s, %s)",
            (agent, rule, value))

    def close(self) -> None:
        with self._all_lock:
            for db in self._all:
                try:
                    db.close()
                except Exception:
                    pass
            self._all.clear()
        self._local = threading.local()


def open_usage(spec: str):
    """'memory', a SQLite file path, or a postgresql:// URL."""
    if spec == "memory":
        return MemoryUsage()
    if spec.startswith(("postgres://", "postgresql://")):
        return PostgresUsage(spec)
    return SqliteUsage(spec)
