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

from ..guard import AuditLog, Guard
from ..identity import AgentRegistry
from ..policy import Policy
from .proxy import McpProxy, _log

DEFAULT_AUDIT = Path.home() / ".securegent" / "audit.jsonl"


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
    p.add_argument("--audit", default=str(DEFAULT_AUDIT), help=f"audit log file (default: {DEFAULT_AUDIT})")
    p.add_argument("--kill-switch", metavar="FILE",
                   help="if this file exists, every tool call is blocked (delete it to resume)")
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
    # stdin/stdout carry the protocol, so there is no terminal to ask a human.
    # Calls that need approval are refused (approvals will come with the web dashboard).
    guard = Guard(registry, policy, AuditLog(args.audit), approver=lambda request: False)

    _log(f"policy={args.policy} agent={args.agent_id} scopes={scopes} audit={args.audit}")
    proxy = McpProxy(command, guard, token, args.server_name,
                     sys.stdin.buffer, sys.stdout.buffer,
                     hide_out_of_scope_tools=not args.show_all_tools,
                     kill_switch=args.kill_switch)
    return proxy.run()


if __name__ == "__main__":
    sys.exit(main())
