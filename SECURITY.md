# Security Policy

Securegent is a security tool, so we take bugs in it seriously, especially any way to
make the guard allow an action that policy should block.

## Reporting a vulnerability

Please **do not** open a public GitHub issue. Instead, use GitHub's private
vulnerability reporting: go to the repository's **Security** tab and click
**Report a vulnerability**.

Include:
- what you did (steps or a minimal script),
- what you expected the guard to do,
- what it did instead.

We aim to reply within 7 days.

## Supported versions

Securegent is in early development (0.x). Only the latest release gets security fixes.

## Known limitations

The full, current list with mitigations is in
[docs/design.md](docs/design.md#known-bypasses-and-limitations), and reproducible bypasses are in
[attacks/known-bypasses/](attacks/known-bypasses/). The ones that matter most when deploying:

- The agent registry and token revocations live in memory; restarting the process loses them.
- If `SECUREGENT_SECRET` is not set, a random signing key is generated per process.
- The audit log is a local file and is not tamper-evident. Forward it to a SIEM in real time.
- Taint tracking matches copied text; encoded, paraphrased or translated data is not caught.
- Path rules match the text of the path the AI sends; symlinks are not resolved. Keep the
  MCP server itself limited to the folders it needs.
- Approvals and the kill switch are files in `~/.securegent`. Anyone who can write there can
  approve requests or stop agents: keep it private to your user and never give an agent file
  access to it (`pack:mcp-filesystem` blocks it).
- The dashboard is for one person on one computer. Its token is in the link printed when it
  starts; treat that link like a password.

## Fixed security issues

| Issue | Affected | Fixed in |
|---|---|---|
| Allowed tool calls ran before their audit entry was written; an audit-log failure left an action unrecorded | 0.1.0, 0.2.0 | 0.3.0 |
| `--upstream-url` followed HTTP redirects and re-sent `--header` values (e.g. a bearer token) to the redirect target | 0.2.0 | 0.3.0 |
| An agent with file access to `~/.securegent` could approve its own requests (`pack:mcp-filesystem` now denies it) | 0.1.0, 0.2.0 | 0.3.0 |
| A negative or NaN amount could shrink a running total | 0.1.0 | 0.2.0 |
