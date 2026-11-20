"""How much time does the guard add per tool call?  python scripts/benchmark.py

Measures Guard.check() (identity + scope + policy + limits + audit write) with the bundled
india-finance pack, with and without taint data in the session, and the raw policy
evaluation alone. Prints medians and 99th percentiles in microseconds.
"""

import statistics
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from securegent import AgentRegistry, AuditLog, Guard, Policy  # noqa: E402

N = 3000


def timed(fn, n=N):
    samples = []
    for _ in range(n):
        t = time.perf_counter_ns()
        fn()
        samples.append((time.perf_counter_ns() - t) / 1000)
    samples.sort()
    return statistics.median(samples), samples[int(len(samples) * 0.99)]


def main():
    policy = Policy.from_file("pack:india-finance")
    with tempfile.TemporaryDirectory() as tmp:
        reg = AgentRegistry(secret=b"bench")
        reg.register("finance-assistant", owner="priya@acme.com", allowed_scopes=["*"])
        guard = Guard(reg, policy, AuditLog(Path(tmp) / "audit.jsonl"))
        token = reg.issue_token("finance-assistant", ["*"], ttl_seconds=3600, task="bench")
        email = {"to": "finance@acme.com", "subject": "INV-2041 paid", "body": "Paid Rs 42,000 for INV-2041."}

        rows = [("policy evaluation only (india-finance, email.send)",
                 timed(lambda: policy.evaluate("finance-assistant", "email.send", email)))]
        rows.append(("Guard.check, email.send (auth + policy + audit write)",
                     timed(lambda: guard.check(token, "email.send", email))))
        # Give the session 50 KB of labelled source text, as after reading files and pages.
        for i in range(50):
            guard.taint.record(reg.verify(token)["jti"], "personal", "files.read",
                               f"row {i}: customer{i}@example.com, 98765{i:05d}, " + "lorem ipsum dolor " * 50)
        rows.append(("Guard.check, email.send, with 50 KB of taint data",
                     timed(lambda: guard.check(token, "email.send", email))))

    print(f"{N} runs each, Python {sys.version.split()[0]}\n")
    print(f"{'what':58} {'median':>10} {'p99':>10}")
    for name, (med, p99) in rows:
        print(f"{name:58} {med:8.0f}us {p99:8.0f}us")


if __name__ == "__main__":
    main()
