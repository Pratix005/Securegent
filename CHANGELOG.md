# Changelog

## 0.2.0 (2026-11-20)

### New

- **Taint tracking.** Policies can name *source* tools and label their output
  (`untrusted`, `confidential`, ...). New conditions `tainted`, `not_tainted` and
  `session_tainted` let rules check where an argument's data came from, e.g. "deny any URL
  that carries data read from `customers.csv`". Works through the MCP proxy; evidence is
  logged and shown on the dashboard.
- **SIEM export** (`securegent-siem`): the audit log as Elastic Common Schema JSON or CEF, in
  batch or live (`--follow`), optionally over syslog. Severities, MITRE ATLAS tags for
  likely prompt injection and data leakage, and ready-made Wazuh rules (including "agent
  blocked 5 times in 2 minutes").
- **MCP proxy: remote servers.** `--upstream-url` connects to MCP servers over Streamable
  HTTP; `--header` adds headers, reading `${VAR}` from the environment.
- **MCP proxy: serve over HTTP.** `--listen HOST:PORT` for AI apps that connect by URL.
  One upstream connection and token per client session, origin checks, optional bearer token.
- **MCP tool poisoning checks.** Tool names, descriptions and schemas are scanned for
  hidden instructions, secret-file grabs and invisible characters; definitions are pinned
  to catch rug pulls. `--tool-check block|warn|off` (default `block`).
- **Slack approvals.** `--slack-channel` / `--slack-approvers`: approve or deny with a
  reaction, no public URL needed. Only listed users count; any deny wins. Works alongside
  the dashboard.
- **Persistent running limits.** Limit totals can live in SQLite (`SqliteUsage`), so a
  restart or crash can't reset a daily limit and several processes share one limit. The MCP
  proxy uses `~/.securegent/usage.db` by default (`--usage-db`).
- **Red-team suite: 14 attacks** (was 10): exfiltration through an allowlisted website,
  one-record-at-a-time leaks, and attacks written in Hindi and Hinglish. Policy-mode replays
  now include the agent's normal reads first, so taint rules can be tested.
- Audit entries now include `stage` (which check decided) and a unique `id`.

### Fixed

- A negative or NaN amount could shrink a running total and make room for more spending.
  Such amounts now never fit under a limit.

### Changed

- `policies.json` and `pack:india-finance` (now 0.2.0) include taint sources and rules;
  both stop 14/14 attacks while allowing normal work.
- `McpProxy` takes an upstream transport (a command list still works as before).

## 0.1.0 (2026-11-19)

First release: agent identities and signed task-scoped tokens, policy engine with
running limits, audit log, kill switch, red-team suite, MCP proxy (stdio), dashboard with
approvals, policy packs `mcp-filesystem` and `india-finance`.
