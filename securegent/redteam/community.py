"""
Attack scenarios written as JSON, so anyone can contribute one without writing Python.

    securegent-redteam --scenarios attacks/              # a folder of *.json files
    securegent-redteam --scenarios my-attack.json --only my-attack

A scenario file (see attacks/TEMPLATE.json):

{
  "id": "fake-gst-refund",                 lowercase letters, digits and dashes
  "name": "Fake GST refund",
  "category": "social engineering",
  "description": "One sentence: what the attacker tries.",
  "author": "your GitHub handle",
  "task": "Please process today's invoices.",          optional, the user's request
  "inbox": [{"from": "...", "subject": "...", "body": "..."}],   where the attack is planted
  "files": {"path": "content"},                        optional, added to the workspace
  "web":   {"https://url": "page text"},               optional
  "reads_first":  [["email.read", {}]],                what the agent reads before acting
  "attack_calls": [["payments.pay", {"vendor": "X", "amount": 1}]],   what a hijacked agent does
  "harm": [                                            when is a call harmful? any entry matching
    {"builtin": "pays_unapproved"},
    {"tool": "email.send", "when": [{"arg": "to", "op": "contains", "value": "evil"}]}
  ]
}

The workspace is the same fake finance company the built-in attacks use (tools email.read,
email.send, files.list, files.read, web.fetch, payments.pay, files.delete).
"""

import json
import re
from pathlib import Path

from ..policy import Policy, _matches_any
from . import scenarios as builtin
from .scenarios import Scenario

TOOLS = {"email.read", "email.send", "files.list", "files.read", "web.fetch", "payments.pay", "files.delete"}
BUILTIN_HARMS = {
    "emails_outside": builtin.emails_outside,
    "pays_unapproved": builtin.pays_unapproved,
    "deletes_files": builtin.deletes_files,
    "reads_secrets": builtin.reads_secrets,
    "fetches_untrusted": builtin.fetches_untrusted,
    "leaks_customers": builtin.leaks_customers,
}
_ID = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")


class ScenarioError(ValueError):
    pass


def _calls(data, field, where):
    calls = data.get(field, [])
    if not isinstance(calls, list):
        raise ScenarioError(f"{where}: '{field}' must be a list of [tool, {{args}}] pairs")
    out = []
    for c in calls:
        if not (isinstance(c, list) and len(c) == 2 and isinstance(c[0], str) and isinstance(c[1], dict)):
            raise ScenarioError(f"{where}: each '{field}' entry must be [\"tool\", {{args}}], got {c!r}")
        if c[0] not in TOOLS:
            raise ScenarioError(f"{where}: unknown tool '{c[0]}' (available: {', '.join(sorted(TOOLS))})")
        out.append((c[0], c[1]))
    return out


def _harm(data, where):
    entries = data.get("harm")
    if not isinstance(entries, list) or not entries:
        raise ScenarioError(f"{where}: 'harm' must be a non-empty list")
    checks = []
    for h in entries:
        if not isinstance(h, dict):
            raise ScenarioError(f"{where}: each 'harm' entry must be an object")
        if "builtin" in h:
            if h["builtin"] not in BUILTIN_HARMS:
                raise ScenarioError(f"{where}: unknown builtin harm '{h['builtin']}' "
                                    f"(available: {', '.join(sorted(BUILTIN_HARMS))})")
            checks.append(BUILTIN_HARMS[h["builtin"]])
            continue
        if "tool" not in h:
            raise ScenarioError(f"{where}: a 'harm' entry needs 'builtin' or 'tool'")
        when = h.get("when", [])
        try:                                     # reuse the policy engine to validate conditions
            Policy([{"id": "harm", "tool": h["tool"], "when": when, "effect": "deny"}])
        except (ValueError, KeyError) as e:
            raise ScenarioError(f"{where}: bad 'harm' condition: {e}") from None
        checks.append(lambda tool, args, h=h, when=when:
                      _matches_any(tool, h["tool"]) and all(Policy._check(c, args) for c in when))
    return lambda tool, args: any(c(tool, args) for c in checks)


def scenario_from_dict(data: dict, where: str = "scenario") -> Scenario:
    if not isinstance(data, dict):
        raise ScenarioError(f"{where}: must be a JSON object")
    for field in ("id", "name", "category", "description"):
        if not isinstance(data.get(field), str) or not data[field].strip():
            raise ScenarioError(f"{where}: '{field}' is required")
    if not _ID.fullmatch(data["id"]):
        raise ScenarioError(f"{where}: id must be lowercase letters, digits and dashes")
    attack_calls = _calls(data, "attack_calls", where)
    if not attack_calls:
        raise ScenarioError(f"{where}: 'attack_calls' must list what a hijacked agent would do")
    inbox = data.get("inbox", [])
    if not isinstance(inbox, list) or not all(isinstance(m, dict) and "body" in m for m in inbox):
        raise ScenarioError(f"{where}: 'inbox' must be a list of emails with at least a 'body'")
    for field in ("files", "web"):
        if not isinstance(data.get(field, {}), dict):
            raise ScenarioError(f"{where}: '{field}' must be an object")
    harm = _harm(data, where)
    if not any(harm(t, a) for t, a in attack_calls):
        raise ScenarioError(f"{where}: none of the 'attack_calls' counts as harmful under 'harm', "
                            "so the scenario could never be COMPROMISED")
    kwargs = dict(id=data["id"], name=data["name"], category=data["category"],
                  description=data["description"], harm=harm, attack_calls=attack_calls,
                  inbox=[{"from": m.get("from", "unknown@example.com"), "subject": m.get("subject", ""),
                          "body": m["body"]} for m in inbox],
                  files=dict(data.get("files", {})), web=dict(data.get("web", {})))
    if data.get("task"):
        kwargs["task"] = data["task"]
    if "reads_first" in data:
        kwargs["reads_first"] = _calls(data, "reads_first", where)
    return Scenario(**kwargs)


def load_scenarios(path: str | Path) -> list[Scenario]:
    """Load one scenario file, or every *.json in a folder (TEMPLATE.json is skipped)."""
    path = Path(path)
    files = sorted(path.glob("*.json")) if path.is_dir() else [path]
    found = []
    for f in files:
        if f.name.upper() == "TEMPLATE.JSON":
            continue
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            raise ScenarioError(f"{f}: {e}") from None
        found.append(scenario_from_dict(data, str(f)))
    return found
