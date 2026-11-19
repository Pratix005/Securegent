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

## Known limitations (v0.1)

- The agent registry is in memory; restarting the process loses agents and revocations.
- If `SECUREGENT_SECRET` is not set, a random signing key is generated per process.
- The audit log is a local file and is not tamper-proof.
- Policies check tool arguments only; they don't yet track where data came from (taint tracking is on the roadmap).
- Path rules match the text of the path the AI sends. They don't resolve symlinks or
  `..` (the sample policy rejects `..` in write paths). Keep the MCP server itself limited
  to the folders it needs.
- The MCP proxy supports the stdio transport only.
- Approvals and the kill switch are files in the state folder (`~/.securegent`). Anyone who can
  write to that folder can approve requests or stop agents, so keep it private to your user.
- The dashboard is for one person on one computer. Its token is in the link printed when it
  starts; treat that link like a password.
