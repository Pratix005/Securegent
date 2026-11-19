"""The Guard: the checkpoint every agent tool call must pass through."""

import json
import time
from pathlib import Path
from typing import Callable

from .identity import AgentRegistry, AuthError
from .policy import ALLOW, APPROVE, DENY, Policy


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

    def write(self, entry: dict) -> None:
        entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), **entry}
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")

    def read(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line]


class Guard:
    def __init__(self, registry: AgentRegistry, policy: Policy, audit: AuditLog,
                 approver: Approver = deny_all_approver):
        self.registry = registry
        self.policy = policy
        self.audit = audit
        self.approver = approver
        self._tools: dict[str, Callable] = {}

    def tool(self, name: str):
        """Decorator to register a function as a guarded tool."""
        def wrap(fn):
            self._tools[name] = fn
            return fn
        return wrap

    def call(self, token: str, tool: str, **args):
        entry = {"tool": tool, "args": args}

        # 1. Who is this? (identity)
        try:
            claims = self.registry.verify(token)
        except AuthError as e:
            self._log(entry, DENY, f"auth: {e}")
            raise Blocked(f"auth: {e}") from None
        entry.update(agent=claims["sub"], on_behalf_of=claims["on_behalf_of"], task=claims["task"])

        # 2. Was this token granted this tool? (scope)
        if not self.registry.has_scope(claims, tool):
            reason = f"tool '{tool}' not in token scopes {claims['scopes']}"
            self._log(entry, DENY, reason)
            raise Blocked(reason)

        if tool not in self._tools:
            self._log(entry, DENY, "unknown tool")
            raise Blocked(f"unknown tool '{tool}'")

        # 3. Is this specific action allowed? (policy)
        decision = self.policy.evaluate(claims["sub"], tool, args)
        entry["rule"] = decision.rule

        if decision.effect == DENY:
            self._log(entry, DENY, decision.reason)
            raise Blocked(decision.reason)

        if decision.effect == APPROVE:
            approved = self.approver({**entry, "reason": decision.reason})
            if not approved:
                self._log(entry, DENY, f"approval refused: {decision.reason}")
                raise Blocked(f"human approval refused: {decision.reason}")
            entry["approved_by_human"] = True

        # 4. Execute and record
        result = self._tools[tool](**args)
        self._log(entry, ALLOW, decision.reason)
        return result

    def _log(self, entry: dict, effect: str, reason: str) -> None:
        self.audit.write({**entry, "decision": effect, "reason": reason})
