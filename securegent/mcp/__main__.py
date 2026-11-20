"""
Run any MCP server (local command or remote URL) behind Securegent.

  python -m securegent.mcp --policy pack:mcp-filesystem --server-name filesystem \\
      -- npx -y @modelcontextprotocol/server-filesystem C:/work

Everything after `--` is the command that starts the real MCP server. For a remote
server use --upstream-url instead:

  python -m securegent.mcp --policy my-policy.json --server-name github \\
      --upstream-url https://api.githubcopilot.com/mcp/ \\
      --header "Authorization: Bearer ${GITHUB_TOKEN}"

Point your MCP client (Claude Desktop, Claude Code, Cursor...) at this command instead.
"""

import argparse
import os
import sys
from pathlib import Path

from ..approvals import DEFAULT_STATE_DIR, FileApprover
from ..guard import AuditLog, Guard
from ..identity import AgentRegistry
from ..policy import Policy
from ..slack import SlackApproval
from ..store import MemoryUsage, SqliteUsage
from .listen import TOKEN_ENV, HttpListener
from .proxy import McpProxy
from .upstream import HttpUpstream, _log, parse_headers


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if "--" in argv:
        split = argv.index("--")
        ours, command = argv[:split], argv[split + 1:]
    else:
        ours, command = argv, []

    p = argparse.ArgumentParser(
        prog="python -m securegent.mcp",
        usage="%(prog)s [options] -- <mcp server command...>\n"
              "       %(prog)s [options] --upstream-url https://host/mcp",
        description="Run an MCP server behind the Securegent policy guard.")
    p.add_argument("--upstream-url", metavar="URL",
                   help="remote MCP server (Streamable HTTP) instead of a local command")
    p.add_argument("--header", action="append", metavar="'Name: value'",
                   help="HTTP header for the remote server, repeatable. ${VAR} is read from the "
                        "environment, e.g. --header 'Authorization: Bearer ${GITHUB_TOKEN}'")
    p.add_argument("--policy", required=True, help="policy JSON file, or a bundled pack like pack:mcp-filesystem")
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
    p.add_argument("--usage-db", metavar="FILE",
                   help="SQLite file for running-limit totals, so limits survive restarts and are "
                        "shared by all proxies using the same file (default: <state-dir>/usage.db; "
                        "'memory' keeps them in this process only)")
    p.add_argument("--approvals", action="store_true",
                   help="wait for a human to approve/deny in the dashboard "
                        "(default: calls that need approval are refused)")
    p.add_argument("--approval-timeout", type=float, default=120,
                   help="seconds to wait for a decision before denying (default: 120)")
    p.add_argument("--slack-channel", metavar="CHANNEL_ID",
                   help="also ask for approvals in this Slack channel (needs --approvals, "
                        "--slack-approvers and SLACK_BOT_TOKEN in the environment)")
    p.add_argument("--slack-approvers", metavar="U1,U2",
                   help="comma-separated Slack user ids allowed to approve or deny")
    p.add_argument("--tool-check", choices=["block", "warn", "off"], default="block",
                   help="scan tool descriptions for hidden instructions and changes (rug pulls): "
                        "block drops such tools, warn only logs them (default: block)")
    p.add_argument("--listen", metavar="HOST:PORT",
                   help="serve the proxy over HTTP at http://HOST:PORT/mcp instead of stdio, for AI "
                        "apps that connect by URL (e.g. 127.0.0.1:8766; the dashboard uses 8765). Each client session gets its "
                        "own upstream connection. Set SECUREGENT_LISTEN_TOKEN to require a bearer token "
                        "(required when HOST is not loopback)")
    p.add_argument("--show-all-tools", action="store_true",
                   help="don't hide tools that are outside the agent's scope")
    args = p.parse_args(ours)
    if args.upstream_url and command:
        p.error("give either --upstream-url or a command after --, not both")
    if args.upstream_url:
        try:
            headers = parse_headers(args.header)
            upstream = HttpUpstream(args.upstream_url, headers)
        except ValueError as e:
            p.error(str(e))
    elif command:
        if args.header:
            p.error("--header only applies to --upstream-url")
        upstream = command
    else:
        p.error("missing the MCP server: a command after --, or --upstream-url")

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
    channels = []
    if args.slack_channel or args.slack_approvers:
        if not args.approvals:
            p.error("--slack-channel needs --approvals")
        try:
            channels.append(SlackApproval(os.environ.get("SLACK_BOT_TOKEN", ""), args.slack_channel or "",
                                          (args.slack_approvers or "").split(",")))
        except ValueError as e:
            p.error(str(e))
    approver = (FileApprover(state, timeout=args.approval_timeout, channels=channels) if args.approvals
                else (lambda request: False))
    usage_db = args.usage_db or str(state / "usage.db")
    usage = MemoryUsage() if usage_db == "memory" else SqliteUsage(usage_db)
    guard = Guard(registry, policy, AuditLog(audit), approver=approver, usage=usage)

    _log(f"policy={args.policy} agent={args.agent_id} scopes={scopes} audit={audit} "
         f"approvals={('dashboard+slack' if channels else 'dashboard') if args.approvals else 'refuse'}")
    options = dict(hide_out_of_scope_tools=not args.show_all_tools,
                   kill_switch=kill_switch, tool_check=args.tool_check)

    if args.listen:
        host, _, port = args.listen.rpartition(":")
        if not host or not port.isdigit():
            p.error("--listen needs HOST:PORT, e.g. 127.0.0.1:8765")

        def make_proxy(client_in, client_out):
            # A fresh token and upstream per client session: taint and tool pins never mix.
            session_token = registry.issue_token(args.agent_id, scopes, ttl_seconds=10 * 365 * 24 * 3600,
                                                 task=f"MCP session: {args.server_name}")
            session_upstream = (HttpUpstream(args.upstream_url, headers) if args.upstream_url
                                else list(command))
            return McpProxy(session_upstream, guard, session_token, args.server_name,
                            client_in, client_out, **options)
        try:
            listener = HttpListener(make_proxy, host.strip("[]"), int(port),
                                    token=os.environ.get(TOKEN_ENV) or None)
        except (ValueError, OSError) as e:
            p.error(str(e))
        try:
            listener.serve_forever()
        except KeyboardInterrupt:
            pass
        return 0

    proxy = McpProxy(upstream, guard, token, args.server_name,
                     sys.stdin.buffer, sys.stdout.buffer, **options)
    return proxy.run()


if __name__ == "__main__":
    sys.exit(main())
