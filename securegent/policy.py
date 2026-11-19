"""Rule-based policy engine: allow, deny, or require human approval per tool call."""

import json
import re
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path

ALLOW, DENY, APPROVE = "allow", "deny", "approve"

_OPS = {
    "equals":       lambda a, v: a == v,
    "not_equals":   lambda a, v: a != v,
    "contains":     lambda a, v: v in str(a),
    "not_contains": lambda a, v: v not in str(a),
    "startswith":   lambda a, v: str(a).lower().startswith(v.lower()),
    "endswith":     lambda a, v: str(a).lower().endswith(v.lower()),
    "not_endswith": lambda a, v: not str(a).lower().endswith(v.lower()),
    "in":           lambda a, v: a in v,
    "not_in":       lambda a, v: a not in v,
    "gt":           lambda a, v: float(a) > float(v),
    "gte":          lambda a, v: float(a) >= float(v),
    "lt":           lambda a, v: float(a) < float(v),
    "lte":          lambda a, v: float(a) <= float(v),
    # Whole-value regex match (case-insensitive). Prefer this over endswith/contains for
    # things like email addresses: "x@evil.ru, a@acme.com" ends with "@acme.com" too.
    "matches":      lambda a, v: re.fullmatch(v, str(a), re.IGNORECASE) is not None,
    "not_matches":  lambda a, v: re.fullmatch(v, str(a), re.IGNORECASE) is None,
}


PACKS_DIR = Path(__file__).parent / "packs"


def list_packs() -> list[str]:
    """Names of the policy packs bundled with Securegent."""
    return sorted(p.stem for p in PACKS_DIR.glob("*.json"))


def resolve_policy_path(path: str | Path) -> Path:
    """A file path, or "pack:<name>" for a bundled pack."""
    text = str(path)
    if text.startswith("pack:"):
        name = text[len("pack:"):]
        if name not in list_packs():
            raise FileNotFoundError(f"no bundled pack '{name}' (available: {', '.join(list_packs())})")
        return PACKS_DIR / f"{name}.json"
    return Path(path)


def _matches_any(name: str, patterns) -> bool:
    """A rule's "agent"/"tool" may be one glob pattern or a list of them."""
    if isinstance(patterns, str):
        patterns = [patterns]
    return any(fnmatch(name, p) for p in patterns)


@dataclass
class Decision:
    effect: str
    reason: str
    rule: str | None = None
    # Optional running total for ALLOW rules, e.g.
    # {"sum_arg": "amount", "max": 100000, "window_seconds": 86400}
    # Once the total in the window would go over max, the call needs human approval.
    limit: dict | None = None


class Policy:
    """Rules are checked in order; the first match wins. No match means deny."""

    def __init__(self, rules: list[dict]):
        for rule in rules:
            if rule.get("effect") not in (ALLOW, DENY, APPROVE):
                raise ValueError(f"rule {rule.get('id')}: effect must be allow/deny/approve")
            for cond in rule.get("when", []):
                if cond["op"] not in _OPS:
                    raise ValueError(f"rule {rule.get('id')}: unknown op '{cond['op']}'")
                if cond["op"] in ("matches", "not_matches"):
                    try:
                        re.compile(cond["value"])
                    except re.error as e:
                        raise ValueError(f"rule {rule.get('id')}: bad regex: {e}") from None
            limit = rule.get("limit")
            if limit is not None:
                if rule["effect"] != ALLOW:
                    raise ValueError(f"rule {rule.get('id')}: 'limit' only makes sense on allow rules")
                if not isinstance(limit.get("max"), (int, float)) or \
                        not isinstance(limit.get("window_seconds"), (int, float)):
                    raise ValueError(f"rule {rule.get('id')}: limit needs numeric 'max' and 'window_seconds'")
        self.rules = rules

    @classmethod
    def from_file(cls, path: str | Path) -> "Policy":
        """Load a policy file, or a bundled pack by name: "pack:india-finance"."""
        return cls(json.loads(resolve_policy_path(path).read_text(encoding="utf-8"))["rules"])

    def evaluate(self, agent_id: str, tool: str, args: dict) -> Decision:
        for rule in self.rules:
            if not _matches_any(agent_id, rule.get("agent", "*")):
                continue
            if not _matches_any(tool, rule.get("tool", "*")):
                continue
            if all(self._check(cond, args) for cond in rule.get("when", [])):
                return Decision(rule["effect"], rule.get("reason", ""), rule.get("id"), rule.get("limit"))
        return Decision(DENY, "no rule allows this action (default deny)")

    @staticmethod
    def _check(cond: dict, args: dict) -> bool:
        if cond["arg"] not in args:
            return False
        try:
            return _OPS[cond["op"]](args[cond["arg"]], cond["value"])
        except (TypeError, ValueError):
            return False
