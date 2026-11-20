"""The Guard: the checkpoint every agent tool call must pass through."""

import json
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Callable

from .identity import AgentRegistry, AuthError
from .policy import ALLOW, APPROVE, DENY, Decision, Policy
from .store import MemoryUsage
from .taint import TaintTracker, TaintView


class Blocked(Exception):
    """Raised when the guard refuses a tool call."""


Approver = Callable[[dict], bool]


def deny_all_approver(request: dict) -> bool:
    return False


class AuditLog:
    """Append-only JSON-lines log of every decision."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write(self, entry: dict) -> None:
        entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "id": uuid.uuid4().hex, **entry}
        line = json.dumps(entry, default=str) + "\n"
        with self._lock, self.path.open("a", encoding="utf-8") as f:
            f.write(line)

    def read(self, last: int | None = None) -> list[dict]:
        if not self.path.exists():
            return []
        lines = [l for l in self.path.read_text(encoding="utf-8").splitlines() if l.strip()]
        if last is not None:
            lines = lines[-last:]
        entries = []
        for line in lines:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:    # a half-written line from another process
                continue
        return entries


class Guard:
    def __init__(self, registry: AgentRegistry, policy: Policy, audit: AuditLog,
                 approver: Approver = deny_all_approver, usage=None):
        """usage: where running-limit totals are kept (store.MemoryUsage by default;
        store.SqliteUsage keeps them across restarts and processes)."""
        self.registry = registry
        self.policy = policy
        self.audit = audit
        self.approver = approver
        self._tools: dict[str, Callable] = {}
        self.usage = usage if usage is not None else MemoryUsage()
        self.taint = TaintTracker()           # where data came from, per token (session)

    def tool(self, name: str):
        """Decorator to register a function as a guarded tool."""
        def wrap(fn):
            self._tools[name] = fn
            return fn
        return wrap

    def call(self, token: str, tool: str, **args):
        """Check the call and, if allowed, run the registered tool function."""
        if tool not in self._tools:
            self._log({"tool": tool, "args": args}, DENY, "unknown tool", "tool")
            raise Blocked(f"unknown tool '{tool}'")
        entry, decision, claims = self._authorize(token, tool, args)
        # Log first, run second: if the allow can't be recorded, the tool never runs.
        self._record(entry, decision, claims, args)
        result = self._tools[tool](**args)
        self._remember(claims, tool, args, result)
        return result

    def observe(self, token: str, tool: str, args: dict, result) -> None:
        """Tell the guard what an allowed call returned (for proxies, which run the tool
        elsewhere). Output of tools the policy lists as sources is remembered for taint."""
        try:
            claims = self.registry.verify(token)
        except AuthError:
            return
        self._remember(claims, tool, args, result)

    def _remember(self, claims: dict, tool: str, args: dict, result) -> None:
        for label in self.policy.source_labels(claims["sub"], tool, args):
            self.taint.record(claims["jti"], label, tool, result)

    def check(self, token: str, tool: str, args: dict) -> None:
        """Check the call without running anything (for proxies that forward the call
        elsewhere). Returns if allowed (and logs it); raises Blocked otherwise."""
        entry, decision, claims = self._authorize(token, tool, args)
        self._record(entry, decision, claims, args)

    def _authorize(self, token: str, tool: str, args: dict):
        entry = {"tool": tool, "args": args}

        # 1. Who is this? (identity)
        try:
            claims = self.registry.verify(token)
        except AuthError as e:
            self._log(entry, DENY, f"auth: {e}", "auth")
            raise Blocked(f"auth: {e}") from None
        entry.update(agent=claims["sub"], on_behalf_of=claims["on_behalf_of"], task=claims["task"])

        # 2. Was this token granted this tool? (scope)
        if not self.registry.has_scope(claims, tool):
            reason = f"tool '{tool}' not in token scopes {claims['scopes']}"
            self._log(entry, DENY, reason, "scope")
            raise Blocked(reason)

        # 3. Is this specific action allowed? (policy, including where the data came from)
        # The human's own words (the task in the token) are trusted, never tainted.
        self.taint.trust(claims["jti"], claims.get("task"), claims.get("on_behalf_of"), claims.get("owner"))
        view = TaintView(self.taint, claims["jti"], args)
        decision = self.policy.evaluate(claims["sub"], tool, args, taint=view)
        entry["rule"] = decision.rule
        if view.evidence:
            entry["taint"] = view.evidence

        # 3b. Running totals: stops "10 payments of 95,000" style splitting.
        # Checking and recording are one atomic step in the usage store, so two calls
        # arriving at the same moment can't both squeeze under the limit.
        if decision.effect == ALLOW and decision.limit:
            limit = decision.limit
            ok, total = self.usage.reserve(claims["sub"], decision.rule, self._limit_value(limit, args),
                                           limit["window_seconds"], limit["max"])
            if not ok:
                what = limit.get("sum_arg") or "calls"
                over = (f"limit exceeded for rule '{decision.rule}': {what} total would be "
                        f"{total:g} (max {limit['max']:g} per {limit['window_seconds']:g}s)")
                decision = Decision(APPROVE, over, decision.rule, decision.limit)

        if decision.effect == DENY:
            self._log(entry, DENY, decision.reason, "policy")
            raise Blocked(decision.reason)

        if decision.effect == APPROVE:
            approved = self.approver({**entry, "reason": decision.reason})
            if not approved:
                self._log(entry, DENY, f"approval refused: {decision.reason}", "approval")
                raise Blocked(f"human approval refused: {decision.reason}")
            entry["approved_by_human"] = True
            if decision.limit:   # human-approved spending still counts toward the total
                self.usage.add(claims["sub"], decision.rule, self._limit_value(decision.limit, args))

        return entry, decision, claims

    def _record(self, entry: dict, decision: Decision, claims: dict, args: dict) -> None:
        """Write the ALLOW to the audit log (limit usage was reserved in _authorize).
        Fails closed: an allow that can't be logged is refused."""
        self._log(entry, ALLOW, decision.reason, "approval" if entry.get("approved_by_human") else "policy",
                  must_record=True)

    @staticmethod
    def _limit_value(limit: dict, args: dict) -> float:
        """The amount this call adds to the running total (1 per call if no sum_arg)."""
        key = limit.get("sum_arg")
        if not key:
            return 1.0
        try:
            value = float(args.get(key, 0))
        except (TypeError, ValueError):
            return float("inf")       # unparseable amounts never slip under a limit
        # A negative (or NaN) amount would shrink the running total and make room for more.
        return value if value >= 0 else float("inf")

    def _log(self, entry: dict, effect: str, reason: str, stage: str, must_record: bool = False) -> None:
        """stage = the check that decided: tool, auth, scope, policy or approval.

        If the audit log can't be written: an allow (must_record) is turned into a refusal,
        so nothing runs unrecorded; a deny still denies, with a warning on stderr."""
        try:
            self.audit.write({**entry, "decision": effect, "reason": reason, "stage": stage})
        except (OSError, ValueError, TypeError) as e:
            if must_record:
                raise Blocked(f"audit log unavailable ({type(e).__name__}: {e}); "
                              "refusing to run a call that can't be recorded") from None
            print(f"[securegent] WARNING: could not write the audit log ({e}); "
                  f"the call was still {effect}ed", file=sys.stderr, flush=True)
