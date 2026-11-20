"""
Send Securegent decisions to a SIEM (Splunk, Elastic, Wazuh, QRadar, ArcSight, ...).

The audit log is converted to one of two standard formats:

  ecs  Elastic Common Schema JSON, one event per line. Elastic and OpenSearch read it as
       is; Wazuh and Splunk read it as plain JSON.
  cef  ArcSight Common Event Format, one line per event. Splunk, QRadar and ArcSight
       understand it, usually over syslog.

    securegent-siem --format ecs --output securegent-ecs.jsonl --follow
    securegent-siem --format cef --syslog siem.example.com:514 --follow

Severity (0-10, also used for ECS event.severity):
  1 allowed   3 allowed after human approval   5 unknown tool / out of scope
  6 denied by policy or approval refused   7 auth failure or kill switch
  8 denied because of tainted data (likely prompt injection or exfiltration)

Taint findings are tagged with MITRE ATLAS techniques: untrusted data steering a call ->
AML.T0051.001 (indirect prompt injection); confidential data leaving -> AML.T0057
(LLM data leakage).
"""

import argparse
import json
import socket
import sys
import time
from datetime import datetime
from pathlib import Path

from . import __version__
from .approvals import DEFAULT_STATE_DIR

ATLAS = {
    "injection": ("AML.T0051.001", "LLM Prompt Injection: Indirect"),
    "leakage": ("AML.T0057", "LLM Data Leakage"),
}


def _stage(e: dict) -> str:
    """Older logs have no 'stage'; work it out from the reason."""
    if e.get("stage"):
        return e["stage"]
    reason = str(e.get("reason", ""))
    if reason.startswith("auth:"):
        return "auth"
    if reason == "unknown tool":
        return "tool"
    if "not in token scopes" in reason:
        return "scope"
    if reason.startswith("approval refused") or e.get("approved_by_human"):
        return "approval"
    return "policy"


def _taint_labels(e: dict) -> list[str]:
    taint = e.get("taint") or {}
    return sorted({ev.get("label") for evs in taint.values() for ev in evs if ev.get("label")})


def severity(e: dict) -> int:
    stage, allowed = _stage(e), e.get("decision") == "allow"
    if allowed:
        return 3 if e.get("approved_by_human") else 1
    if _taint_labels(e):
        return 8
    return {"auth": 7, "tool": 5, "scope": 5}.get(stage, 6)


def techniques(e: dict) -> list[tuple[str, str]]:
    if e.get("decision") == "allow":
        return []
    labels = _taint_labels(e)
    found = []
    if "untrusted" in labels:
        found.append(ATLAS["injection"])
    if any(l != "untrusted" for l in labels):
        found.append(ATLAS["leakage"])
    return found


def _timestamp(e: dict) -> str:
    """Audit timestamps are local time without an offset; SIEMs need the offset."""
    try:
        return datetime.strptime(e["ts"], "%Y-%m-%dT%H:%M:%S").astimezone().isoformat()
    except (KeyError, ValueError, TypeError):
        return datetime.now().astimezone().isoformat(timespec="seconds")


def _message(e: dict) -> str:
    verb = {"allow": "ALLOWED", "deny": "DENIED"}.get(e.get("decision"), str(e.get("decision")).upper())
    return f"{verb} {e.get('agent', '?')} -> {e.get('tool', '?')}: {e.get('reason', '')}"


def to_ecs(e: dict) -> dict:
    allowed = e.get("decision") == "allow"
    sev, labels, techs = severity(e), _taint_labels(e), techniques(e)
    out = {
        "@timestamp": _timestamp(e),
        "message": _message(e),
        "ecs": {"version": "8.11.0"},
        "event": {
            "kind": "event" if allowed else "alert",
            "module": "securegent",
            "dataset": "securegent.audit",
            "category": ["intrusion_detection"],
            "type": ["allowed"] if allowed else ["denied"],
            "outcome": "success" if allowed else "failure",
            "action": e.get("tool"),
            "reason": e.get("reason"),
            "severity": sev,
        },
        "observer": {"vendor": "Securegent", "product": "Securegent", "type": "ai-agent-firewall",
                     "version": __version__},
        "tags": ["securegent", e.get("decision", "unknown")] + (["taint"] if labels else []),
        "securegent": {
            "agent_id": e.get("agent"),
            "decision": e.get("decision"),
            "stage": _stage(e),
            "task": e.get("task"),
            # A string, so arbitrary tool arguments can't explode the SIEM's field mapping.
            "args": json.dumps(e.get("args"), default=str, ensure_ascii=False),
            "approved_by_human": bool(e.get("approved_by_human")),
            "tainted": bool(labels),
        },
    }
    if e.get("id"):
        out["event"]["id"] = e["id"]
    if e.get("on_behalf_of"):
        out["user"] = {"name": e["on_behalf_of"]}
    if e.get("rule"):
        out["rule"] = {"id": e["rule"], "name": e["rule"], "ruleset": "securegent"}
    if labels:
        out["securegent"]["taint_labels"] = labels
        out["securegent"]["taint"] = json.dumps(e.get("taint"), ensure_ascii=False)
    if techs:
        out["threat"] = {"framework": "MITRE ATLAS",
                         "technique": {"id": [t[0] for t in techs], "name": [t[1] for t in techs]}}
    return out


def _cef_header(value) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|")


def _cef_ext(value) -> str:
    return (str(value).replace("\\", "\\\\").replace("=", "\\=")
            .replace("\r", "\\r").replace("\n", "\\n"))


def to_cef(e: dict) -> str:
    stage, decision = _stage(e), e.get("decision", "unknown")
    name = "Tool call allowed" if decision == "allow" else f"Tool call denied ({stage})"
    try:
        rt = int(datetime.fromisoformat(_timestamp(e)).timestamp() * 1000)
    except ValueError:
        rt = int(time.time() * 1000)
    ext = {
        "rt": rt,
        "act": decision,
        "cat": stage,
        "suser": e.get("on_behalf_of"),
        "reason": e.get("reason"),
        "msg": _message(e),
        "externalId": e.get("id"),
        "cs1Label": "agent", "cs1": e.get("agent"),
        "cs2Label": "tool", "cs2": e.get("tool"),
        "cs3Label": "rule", "cs3": e.get("rule"),
        "cs4Label": "taint", "cs4": ",".join(_taint_labels(e)) or None,
        "cs5Label": "atlas", "cs5": ",".join(t[0] for t in techniques(e)) or None,
        "cs6Label": "args", "cs6": json.dumps(e.get("args"), default=str, ensure_ascii=False)[:1000],
    }
    ext_text = " ".join(f"{k}={_cef_ext(v)}" for k, v in ext.items() if v not in (None, ""))
    header = "|".join(_cef_header(x) for x in (
        "Securegent", "Securegent", __version__, f"{stage}-{decision}", name, severity(e)))
    return f"CEF:0|{header}|{ext_text}"


def format_entry(e: dict, fmt: str) -> str:
    return json.dumps(to_ecs(e), ensure_ascii=False) if fmt == "ecs" else to_cef(e)


class SyslogSender:
    """RFC 5424 over UDP, facility local0."""

    def __init__(self, target: str):
        host, _, port = target.rpartition(":")
        if not host or not port.isdigit():
            raise ValueError("--syslog needs HOST:PORT, e.g. siem.example.com:514")
        self.addr = (host.strip("[]"), int(port))
        self.sock = socket.socket(socket.AF_INET6 if ":" in self.addr[0] else socket.AF_INET, socket.SOCK_DGRAM)
        self.hostname = socket.gethostname()

    def send(self, line: str, sev: int) -> None:
        level = 2 if sev >= 8 else 3 if sev >= 7 else 4 if sev >= 5 else 6   # crit/err/warning/info
        pri = 16 * 8 + level
        ts = datetime.now().astimezone().isoformat(timespec="milliseconds")
        msg = f"<{pri}>1 {ts} {self.hostname} securegent - - - {line}"
        self.sock.sendto(msg.encode("utf-8")[:65000], self.addr)


def read_entries(path: Path, follow: bool = False, from_start: bool = True, poll: float = 0.5,
                 stop=lambda: False):
    """Yield audit entries; with follow=True keep waiting for new ones (like tail -f).
    Partial lines are held back until complete; a truncated or replaced file is re-read."""
    pos = 0 if from_start or not path.exists() else path.stat().st_size
    buf = b""
    while True:
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            size = 0
        if size < pos:                              # truncated / rotated
            pos, buf = 0, b""
        if size > pos:
            with path.open("rb") as f:
                f.seek(pos)
                chunk = f.read(size - pos)
            pos += len(chunk)
            buf += chunk
            *lines, buf = buf.split(b"\n")
            for line in lines:
                if line.strip():
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue
        if not follow or stop():
            return
        time.sleep(poll)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="securegent-siem",
                                description="Export Securegent audit events for a SIEM (ECS JSON or CEF).")
    p.add_argument("--audit", default=str(DEFAULT_STATE_DIR / "audit.jsonl"),
                   help=f"audit log to read (default: {DEFAULT_STATE_DIR / 'audit.jsonl'})")
    p.add_argument("--format", choices=["ecs", "cef"], default="ecs",
                   help="ecs: Elastic Common Schema JSON lines (Elastic, Wazuh, Splunk). "
                        "cef: Common Event Format (Splunk, QRadar, ArcSight)")
    p.add_argument("--output", default="-", help="file to append to, or - for stdout (default)")
    p.add_argument("--syslog", metavar="HOST:PORT", help="also send each event over syslog (UDP, RFC 5424)")
    p.add_argument("--follow", action="store_true", help="keep running and export new events as they happen")
    p.add_argument("--from-start", action="store_true",
                   help="with --follow, export the existing log first (default: only new events)")
    p.add_argument("--min-severity", type=int, default=0, help="skip events below this severity (0-10)")
    args = p.parse_args(argv)

    syslog = None
    if args.syslog:
        try:
            syslog = SyslogSender(args.syslog)
        except (ValueError, OSError) as e:
            p.error(str(e))
    out = sys.stdout if args.output == "-" else open(args.output, "a", encoding="utf-8")
    from_start = args.from_start or not args.follow
    count = 0
    try:
        for e in read_entries(Path(args.audit), follow=args.follow, from_start=from_start):
            if not isinstance(e, dict) or severity(e) < args.min_severity:
                continue
            line = format_entry(e, args.format)
            out.write(line + "\n")
            out.flush()
            if syslog:
                syslog.send(line, severity(e))
            count += 1
    except KeyboardInterrupt:
        pass
    finally:
        if out is not sys.stdout:
            out.close()
    if not args.follow:
        print(f"[securegent] exported {count} event(s) as {args.format}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
