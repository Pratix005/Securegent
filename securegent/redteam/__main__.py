"""
Securegent red-team suite: attack your agent, get a security score.

  python -m securegent.redteam                          # policy mode, instant, no AI
  python -m securegent.redteam --no-guard               # baseline without Securegent
  python -m securegent.redteam --mode agent             # real AI agent (local Ollama, free)
  python -m securegent.redteam --mode agent --backend claude
  python -m securegent.redteam --only fake-cfo-wire,split-payment --json report.json
"""

import argparse
import json
import sys
from pathlib import Path

from ..policy import Policy
from . import runner
from .scenarios import SCENARIOS

ICONS = {runner.RESISTED: "OK  ", runner.BLOCKED: "OK  ", runner.COMPROMISED: "FAIL", runner.ERROR: "ERR "}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m securegent.redteam",
                                description="Run prompt-injection attacks against a Securegent-protected agent.")
    p.add_argument("--mode", choices=["policy", "agent"], default="policy",
                   help="policy: replay attacks into the guard (instant). agent: run a real AI agent.")
    p.add_argument("--policy", default="policies.json",
                   help="policy file to test, or a bundled pack like pack:india-finance (default: policies.json)")
    p.add_argument("--no-guard", action="store_true", help="baseline run with no Securegent protection")
    p.add_argument("--backend", choices=["ollama", "claude"], default="ollama", help="agent mode: which AI")
    p.add_argument("--model", help="agent mode: model name (default depends on backend)")
    p.add_argument("--agent-id", default=runner.DEFAULT_AGENT_ID,
                   help=f"agent name your policy rules use (default: {runner.DEFAULT_AGENT_ID})")
    p.add_argument("--only", help="comma-separated scenario ids to run")
    p.add_argument("--list", action="store_true", help="list scenarios and exit")
    p.add_argument("--json", metavar="FILE", help="also write a JSON report")
    p.add_argument("--quiet", action="store_true", help="don't print each tool call in agent mode")
    args = p.parse_args(argv)

    if args.list:
        for s in SCENARIOS:
            print(f"{s.id:22} {s.category:32} {s.name}")
        return 0

    scenarios = SCENARIOS
    if args.only:
        wanted = {x.strip() for x in args.only.split(",")}
        unknown = wanted - {s.id for s in SCENARIOS}
        if unknown:
            p.error(f"unknown scenario id(s): {', '.join(sorted(unknown))}  (see --list)")
        scenarios = [s for s in SCENARIOS if s.id in wanted]

    policy = None
    if not args.no_guard:
        try:
            policy = Policy.from_file(args.policy)
        except FileNotFoundError as e:
            p.error(f"policy not found: {args.policy} ({e})")

    backend = model = None
    if args.mode == "agent":
        from ..backends import get_backend
        backend = get_backend(args.backend)
        model = args.model or backend.DEFAULT_MODEL

    target = "NO GUARD (baseline)" if policy is None else f"Securegent policy: {args.policy}"
    how = "policy replay" if args.mode == "policy" else f"live agent ({args.backend}: {model})"
    print(f"\nSecuregent Red-Team Suite  |  {len(scenarios)} attacks  |  {how}  |  {target}\n")

    wrongly_blocked = runner.check_normal_work(policy, args.agent_id)
    if wrongly_blocked:
        print(f"WARNING: your policy also blocks normal work for agent '{args.agent_id}':")
        for tool, call_args, reason in wrongly_blocked:
            print(f"  - {tool} {call_args}: {reason}")
        print("  A policy that blocks everything scores well but is useless. Check --agent-id and your rules.\n")
    else:
        print("Normal-work check: passed (the real invoice can be paid and confirmed)\n")

    def on_call(tool, call_args, verdict):
        if not args.quiet:
            shown = ", ".join(f"{k}={str(v)[:40]!r}" for k, v in call_args.items())
            print(f"      {verdict:7} {tool}({shown})")

    results = []
    for i, s in enumerate(scenarios, 1):
        print(f"[{i:2}/{len(scenarios)}] {s.name}  ({s.category})", flush=True)
        if args.mode == "policy":
            r = runner.run_policy(s, policy, args.agent_id)
        else:
            r = runner.run_agent(s, policy, backend, model, on_call=on_call, agent_id=args.agent_id)
        results.append(r)
        line = f"      {ICONS[r.outcome]} {r.outcome}"
        if r.outcome == runner.COMPROMISED:
            e = next(e for e in r.harmful if e["decision"] == "allow")
            line += f": {e['tool']} {e['args']} was ALLOWED"
        elif r.outcome == runner.BLOCKED:
            line += f": {r.harmful[0]['reason']}"
        if r.note:
            line += f"  [{r.note}]"
        if args.mode == "agent":
            line += f"  ({r.seconds:.0f}s)"
        print(line, flush=True)

    safe, total, grade = runner.score(results)
    counts = {o: sum(r.outcome == o for r in results)
              for o in (runner.RESISTED, runner.BLOCKED, runner.COMPROMISED, runner.ERROR)}
    print("\n" + "-" * 70)
    print(f"Score: {safe}/{total} attacks stopped   Grade: {grade}")
    print("  " + "   ".join(f"{k.lower()}: {v}" for k, v in counts.items() if v or k != runner.ERROR))
    failed = [r for r in results if r.outcome == runner.COMPROMISED]
    if failed:
        print("\nFix these:")
        for r in failed:
            print(f"  - {r.scenario.id}: {r.scenario.description}")
    print()

    if args.json:
        report = {
            "mode": args.mode, "backend": args.backend if args.mode == "agent" else None, "model": model,
            "guarded": policy is not None, "policy": None if policy is None else args.policy,
            "score": {"stopped": safe, "total": total, "grade": grade}, "counts": counts,
            "normal_work_blocked": [{"tool": t, "args": a, "reason": r} for t, a, r in wrongly_blocked],
            "results": [{"id": r.scenario.id, "name": r.scenario.name, "category": r.scenario.category,
                         "outcome": r.outcome, "note": r.note, "seconds": round(r.seconds, 1),
                         "harmful_calls": r.harmful, "all_calls": r.attempts} for r in results],
        }
        Path(args.json).write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        print(f"JSON report written to {args.json}\n")

    return 0 if not failed and not wrongly_blocked else 1


if __name__ == "__main__":
    sys.exit(main())
