"""
Run any stdio MCP server behind Securegent.

  python -m securegent.mcp --policy policies/mcp-filesystem.json --server-name filesystem \\
      -- npx -y @modelcontextprotocol/server-filesystem C:/work

Everything after `--` is the command that starts the real MCP server.
Point your MCP client (Claude Desktop, Claude Code, Cursor...) at this command instead.
"""

import argparse
import sys
from pathlib import Path

from ..approvals import DEFAULT_STATE_DIR, FileApprover
from ..guard import AuditLog, Guard
from ..identity import AgentRegistry
from ..policy import Policy
from .proxy import McpProxy, _log


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if "--" not in argv:
        print("usage: python -m securegent.mcp [options] -- <mcp server command...>", file=sys.stderr)
        return 2
    split = argv.index("--")
    ours, command = argv[:split], argv[split + 1:]

    p = argparse.ArgumentParser(prog="python -m securegent.mcp",
                                description="Run an MCP server behind the Securegent policy guard.")
    p.add_argument("--policy", required=True, help="policy JSON file")
    p.add_argument("--server-name", required=True,
                   help="name used in policies: tools become '<server-name>.<tool>'")
    p.add_argument("--agent-id", default="mcp-agent", help="agent name your policy rules use (default: mcp-agent)")
    p.add_argument("--scopes", default=None,
                   help="comma-separated tool scopes for this agent (default: '<server-name>.*')")
    p.add_argument("--state-dir", default=str(DEFAULT_STATE_DIR),
                   help=f"folder shared with the dashboard (default: {DEFAULT_STATE_DIR})")
    p.add_argument("--audit", help="audit log file (default: <state-dir>/audit.jsonl)")
    p.add_argument("--kill-switch", metavar="FILE",
                   help="if this file exists, every tool call is blocked "
                        "(default: <state-dir>/KILL_SWITCH, toggled by the dashboard)")
    p.add_argument("--approvals", action="store_true",
                   help="wait for a human to approve/deny in the dashboard "
                        "(default: calls that need approval are refused)")
    p.add_argument("--approval-timeout", type=float, default=120,
                   help="seconds to wait for a decision before denying (default: 120)")
    p.add_argument("--show-all-tools", action="store_true",
                   help="don't hide tools that are outside the agent's scope")
    args = p.parse_args(ours)
    if not command:
        p.error("missing MCP server command after --")

    policy = Policy.from_file(args.policy)
    scopes = [s.strip() for s in args.scopes.split(",")] if args.scopes else [f"{args.server_name}.*"]
    registry = AgentRegistry()
    registry.register(args.agent_id, owner="local-user", allowed_scopes=scopes)
    token = registry.issue_token(args.agent_id, scopes, ttl_seconds=10 * 365 * 24 * 3600,
                                 task=f"MCP session: {args.server_name}")
    state = Path(args.state_dir)
    audit = args.audit or str(state / "audit.jsonl")
    kill_switch = args.kill_switch or str(state / "KILL_SWITCH")
    # stdin/stdout carry the protocol, so there is no terminal to ask a human:
    # approvals go through the dashboard, or are refused.
    approver = (FileApprover(state, timeout=args.approval_timeout) if args.approvals
                else (lambda request: False))
    guard = Guard(registry, policy, AuditLog(audit), approver=approver)

    _log(f"policy={args.policy} agent={args.agent_id} scopes={scopes} audit={audit} "
         f"approvals={'dashboard' if args.approvals else 'refuse'}")
    proxy = McpProxy(command, guard, token, args.server_name,
                     sys.stdin.buffer, sys.stdout.buffer,
                     hide_out_of_scope_tools=not args.show_all_tools,
                     kill_switch=kill_switch)
    return proxy.run()


if __name__ == "__main__":
    sys.exit(main())
