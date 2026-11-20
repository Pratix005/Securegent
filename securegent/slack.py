"""
Approve or deny agent actions from Slack, with no public URL or webhook server.

The bot posts each approval request to a channel; an approver reacts with
:white_check_mark: to approve or :x: to deny. Securegent polls the reactions, so it works
from a laptop behind NAT. The message is then updated with the outcome.

Security:
  - Only the Slack user ids you list may decide. Reactions from anyone else are ignored.
  - If an approver reacts with both, or approvers disagree, the answer is deny.
  - The bot token is read from the SLACK_BOT_TOKEN environment variable, never from the
    command line. Bot scopes needed: chat:write, reactions:read.

Use it with FileApprover (the dashboard): whichever answers first wins.

    approver = FileApprover(state_dir, channels=[SlackApproval(token, "C0123", ["U0456"])])
"""

import json
import sys
import urllib.error
import urllib.parse
import urllib.request

APPROVE = {"white_check_mark", "heavy_check_mark", "+1", "thumbsup"}
DENY = {"x", "no_entry", "no_entry_sign", "-1", "thumbsdown"}


def _log(msg: str) -> None:
    print(f"[securegent] {msg}", file=sys.stderr, flush=True)


class SlackError(Exception):
    pass


_HINTS = {
    "missing_scope": "add the bot scopes chat:write and reactions:read, then Reinstall to Workspace",
    "not_in_channel": "invite the bot: type /invite @<your app> in the channel",
    "channel_not_found": "use the channel id (starts with C), not its name, and invite the bot",
    "invalid_auth": "SLACK_BOT_TOKEN must be the Bot User OAuth Token (xoxb-...)",
    "token_revoked": "the token was revoked; reinstall the app and use the new token",  # nosec B105: not a password: a variable name or message
}


def _hint(error: str) -> str:
    for code, hint in _HINTS.items():
        if code in error:
            return f" - fix: {hint}"
    return ""


class SlackApproval:
    """An approval channel for FileApprover: start() posts, poll() reads the answer."""

    poll_interval = 3.0          # seconds between reactions.get calls (Slack rate limits)

    def __init__(self, token: str, channel: str, approvers: list[str],
                 api_base: str = "https://slack.com/api", timeout: float = 15):
        if not token:
            raise ValueError("Slack approvals need a bot token in SLACK_BOT_TOKEN")
        if not channel:
            raise ValueError("Slack approvals need a channel id")
        approvers = [a.strip() for a in approvers if a.strip()]
        if not approvers:
            raise ValueError("Slack approvals need at least one approver user id (e.g. U0123ABCD), "
                             "otherwise anyone in the channel could approve")
        self.token, self.channel, self.approvers = token, channel, set(approvers)
        self.api_base, self.timeout = api_base.rstrip("/"), timeout

    # --- Slack Web API ----------------------------------------------------------------
    def _api(self, method: str, payload: dict | None = None, query: dict | None = None) -> dict:
        url = f"{self.api_base}/{method}"
        headers = {"Authorization": f"Bearer {self.token}"}
        data = None
        if payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json; charset=utf-8"
        if query:
            url += "?" + urllib.parse.urlencode(query)
        req = urllib.request.Request(url, data=data, headers=headers, method="POST" if data else "GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # nosec B310: scheme is fixed https or checked to be http(s)
                body = json.loads(resp.read())
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise SlackError(f"{method}: {getattr(e, 'reason', e)}") from None
        if not body.get("ok"):
            raise SlackError(f"{method}: {body.get('error', 'unknown error')}")
        return body

    # --- approval channel -------------------------------------------------------------
    def start(self, request_id: str, request: dict, timeout: float):
        """Post the request. Returns a handle, or None if Slack could not be reached."""
        args = json.dumps(request.get("args"), default=str, ensure_ascii=False, indent=1)
        if len(args) > 1500:
            args = args[:1500] + "\n..."
        mentions = " ".join(f"<@{u}>" for u in sorted(self.approvers))
        text = (f":warning: *Securegent approval needed* {mentions}\n"
                f"*Agent:* `{request.get('agent', '?')}` acting for {request.get('on_behalf_of', '?')}\n"
                f"*Action:* `{request.get('tool', '?')}`\n"
                f"*Why it needs you:* {request.get('reason', '')}\n"
                f"```{args}```\n"
                f"React :white_check_mark: to approve or :x: to deny. No answer in "
                f"{int(timeout)} s means deny. (request {request_id[:8]})")
        try:
            msg = self._api("chat.postMessage", {"channel": self.channel, "text": text,
                                                 "unfurl_links": False, "unfurl_media": False})
        except SlackError as e:
            _log(f"Slack approval request not sent ({e}){_hint(str(e))}; use the dashboard")
            return None
        return {"channel": msg.get("channel", self.channel), "ts": msg["ts"], "text": text}

    def poll(self, handle) -> bool | None:
        """True = approved, False = denied, None = no answer yet."""
        try:
            body = self._api("reactions.get", query={"channel": handle["channel"],
                                                     "timestamp": handle["ts"], "full": "true"})
        except SlackError as e:
            _log(f"could not read Slack reactions: {e}")
            return None
        approved_by, denied_by = set(), set()
        for r in body.get("message", {}).get("reactions", []):
            name = str(r.get("name", "")).split("::")[0]       # strip skin tones
            users = set(r.get("users", [])) & self.approvers
            if name in APPROVE:
                approved_by |= users
            elif name in DENY:
                denied_by |= users
        if denied_by:
            handle["by"] = sorted(denied_by)
            return False
        if approved_by:
            handle["by"] = sorted(approved_by)
            return True
        return None

    def finish(self, handle, approved: bool | None, where: str) -> None:
        """Update the message with the outcome. where = here, dashboard, other or timeout."""
        if where == "timeout":
            outcome = ":hourglass: *Expired: denied* (nobody answered in time)"
        else:
            who = {"here": " by " + ", ".join(f"<@{u}>" for u in handle.get("by", [])),
                   "dashboard": " in the dashboard"}.get(where, " in another app")
            outcome = (":white_check_mark: *Approved*" if approved else ":x: *Denied*") + who
        lines = handle["text"].splitlines()
        text = "\n".join(lines[:-1] + [outcome])
        try:
            self._api("chat.update", {"channel": handle["channel"], "ts": handle["ts"], "text": text})
        except SlackError as e:
            _log(f"could not update the Slack message: {e}")
