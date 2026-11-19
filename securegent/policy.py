"""Rule-based policy engine: allow, deny, or require human approval per tool call."""

import json
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path

ALLOW, DENY, APPROVE = "allow", "deny", "approve"

_OPS = {
    "equals":       lambda a, v: a == v,
    "not_equals":   lambda a, v: a != v,
    "contains":     lambda a, v: v in str(a),
    "not_contains": lambda a, v: v not in str(a),
    "endswith":     lambda a, v: str(a).lower().endswith(v.lower()),
    "not_endswith": lambda a, v: not str(a).lower().endswith(v.lower()),
    "in":           lambda a, v: a in v,
    "not_in":       lambda a, v: a not in v,
    "gt":           lambda a, v: float(a) > float(v),
    "gte":          lambda a, v: float(a) >= float(v),
    "lt":           lambda a, v: float(a) < float(v),
    "lte":          lambda a, v: float(a) <= float(v),
}


@dataclass
class Decision:
    effect: str
    reason: str
    rule: str | None = None


class Policy:
    """Rules are checked in order; the first match wins. No match means deny."""

    def __init__(self, rules: list[dict]):
        for rule in rules:
            if rule.get("effect") not in (ALLOW, DENY, APPROVE):
                raise ValueError(f"rule {rule.get('id')}: effect must be allow/deny/approve")
            for cond in rule.get("when", []):
                if cond["op"] not in _OPS:
                    raise ValueError(f"rule {rule.get('id')}: unknown op '{cond['op']}'")
        self.rules = rules

    @classmethod
    def from_file(cls, path: str | Path) -> "Policy":
        return cls(json.loads(Path(path).read_text(encoding="utf-8"))["rules"])

    def evaluate(self, agent_id: str, tool: str, args: dict) -> Decision:
        for rule in self.rules:
            if not fnmatch(agent_id, rule.get("agent", "*")):
                continue
            if not fnmatch(tool, rule.get("tool", "*")):
                continue
            if all(self._check(cond, args) for cond in rule.get("when", [])):
                return Decision(rule["effect"], rule.get("reason", ""), rule.get("id"))
        return Decision(DENY, "no rule allows this action (default deny)")

    @staticmethod
    def _check(cond: dict, args: dict) -> bool:
        if cond["arg"] not in args:
            return False
        try:
            return _OPS[cond["op"]](args[cond["arg"]], cond["value"])
        except (TypeError, ValueError):
            return False
