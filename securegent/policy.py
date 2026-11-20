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

# Taint conditions (see taint.py). "value" is a label, or omitted for any label.
#   {"arg": "url", "op": "tainted", "value": "confidential"}
#   {"arg": "to",  "op": "not_tainted"}
#   {"op": "session_tainted", "value": "untrusted"}       (no "arg")
_TAINT_OPS = {"tainted", "not_tainted", "session_tainted"}
# "arg": "*" applies a condition to every argument: e.g. a secret in any of them.


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


def _validate_conditions(where: str, conds, allow_taint: bool) -> None:
    for cond in conds:
        op = cond.get("op")
        if op in _TAINT_OPS:
            if not allow_taint:
                raise ValueError(f"{where}: taint conditions can't be used here")
            if op != "session_tainted" and "arg" not in cond:
                raise ValueError(f"{where}: '{op}' needs an 'arg'")
            continue
        if op not in _OPS:
            raise ValueError(f"{where}: unknown op '{op}'")
        if "arg" not in cond:
            raise ValueError(f"{where}: condition '{op}' needs an 'arg'")
        if op in ("matches", "not_matches"):
            try:
                re.compile(cond["value"])
            except re.error as e:
                raise ValueError(f"{where}: bad regex: {e}") from None


class Policy:
    """Rules are checked in order; the first match wins. No match means deny.

    `sources` (optional) say which tools' output to remember for taint tracking:
    [{"tool": "email.read", "label": "untrusted", "when": [...]}, ...]
    """

    def __init__(self, rules: list[dict], sources: list[dict] | None = None):
        for src in sources or []:
            if not isinstance(src.get("label"), str) or not src["label"]:
                raise ValueError(f"source for {src.get('tool')}: needs a 'label'")
            _validate_conditions(f"source for {src.get('tool')}", src.get("when", []), allow_taint=False)
        self.sources = list(sources or [])
        for rule in rules:
            if rule.get("effect") not in (ALLOW, DENY, APPROVE):
                raise ValueError(f"rule {rule.get('id')}: effect must be allow/deny/approve")
            _validate_conditions(f"rule {rule.get('id')}", rule.get("when", []), allow_taint=True)
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
        data = json.loads(resolve_policy_path(path).read_text(encoding="utf-8"))
        return cls(data["rules"], data.get("sources"))

    def source_labels(self, agent_id: str, tool: str, args: dict) -> list[str]:
        """Labels to give this call's output (empty: not a source)."""
        return list(dict.fromkeys(
            s["label"] for s in self.sources
            if _matches_any(agent_id, s.get("agent", "*")) and _matches_any(tool, s.get("tool", "*"))
            and all(self._check(c, args) for c in s.get("when", []))))

    def evaluate(self, agent_id: str, tool: str, args: dict, taint=None) -> Decision:
        """`taint` is a taint.TaintView; without one, taint conditions never match."""
        for rule in self.rules:
            if not _matches_any(agent_id, rule.get("agent", "*")):
                continue
            if not _matches_any(tool, rule.get("tool", "*")):
                continue
            if all(self._check(cond, args, taint) for cond in rule.get("when", [])):
                return Decision(rule["effect"], rule.get("reason", ""), rule.get("id"), rule.get("limit"))
        return Decision(DENY, "no rule allows this action (default deny)")

    @staticmethod
    def _check(cond: dict, args: dict, taint=None) -> bool:
        op = cond["op"]
        if cond.get("arg") == "*" and op != "session_tainted":
            # "Any argument": positive conditions need one argument to match, negative
            # ones (not_...) need every argument to pass. No arguments never matches.
            if not args:
                return False
            results = (Policy._check({**cond, "arg": name}, args, taint) for name in args)
            return all(results) if op.startswith("not_") else any(results)
        if op in _TAINT_OPS:
            if taint is None:
                return False
            want = cond.get("value")
            if op == "session_tainted":
                labels = taint.session_labels()
                return bool(labels) if want is None else want in labels
            if cond["arg"] not in args:
                return False
            labels = taint.arg_labels(cond["arg"])
            hit = bool(labels) if want is None else want in labels
            return hit if op == "tainted" else not hit
        if cond["arg"] not in args:
            return False
        try:
            return _OPS[cond["op"]](args[cond["arg"]], cond["value"])
        except (TypeError, ValueError):
            return False
