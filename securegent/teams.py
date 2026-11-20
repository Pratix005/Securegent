"""
Approve or deny agent actions from Microsoft Teams, with no public URL or webhook server.

Securegent posts each approval request to a Teams chat (or channel) through Microsoft Graph
and polls the reactions: 👍 / ✅ approves, 👎 / ❌ / 😠 denies. Only the people you list
count, and any deny wins. The outcome is posted back.

One-time setup (see README "Teams"):
  1. Register an app in Microsoft Entra ID (Azure portal): "Accounts in this organizational
     directory only", Authentication -> "Allow public client flows" = Yes, and delegated
     Microsoft Graph permissions Chat.ReadWrite, User.ReadBasic.All, offline_access
     (none of these needs an admin). For a channel instead of a chat, also
     ChannelMessage.Send and ChannelMessage.Read.All (the latter needs an admin).
  2. securegent-teams login --tenant <tenant id> --client-id <app id>
     Sign in once with the device code shown. A refresh token is stored in
     ~/.securegent/teams-token.json (readable only by you).
  3. securegent-teams chats      # find the chat id to use
  4. securegent-mcp ... --approvals --teams-target chat:<chat id> --teams-approvers you@college.edu

Targets: "chat:<chat id>" or "channel:<team id>/<channel id>".
"""

import argparse
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .approvals import DEFAULT_STATE_DIR

GRAPH = "https://graph.microsoft.com/v1.0"
LOGIN = "https://login.microsoftonline.com"
SCOPES = "Chat.ReadWrite User.ReadBasic.All offline_access"
CHANNEL_SCOPES = "ChannelMessage.Send ChannelMessage.Read.All"
APPROVE = {"like", "👍", "✅", "✔️", "☑️"}
DENY = {"angry", "👎", "❌", "🚫", "⛔"}


def _log(msg: str) -> None:
    print(f"[securegent] {msg}", file=sys.stderr, flush=True)


class TeamsError(Exception):
    pass


def _request(url: str, data: dict | None = None, token: str | None = None, form: bool = False,
             method: str | None = None, timeout: float = 20) -> dict:
    headers = {"Accept": "application/json"}
    body = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if data is not None:
        if form:
            body = urllib.parse.urlencode(data).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            body = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers, method=method or ("POST" if body else "GET"))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as e:
        try:
            err = json.loads(e.read())
        except (json.JSONDecodeError, OSError):
            err = {}
        error = err.get("error")
        if isinstance(error, dict):                # Graph: {"error": {"code", "message"}}
            detail = f"{error.get('code', '')}: {error.get('message', '')}"
        else:                                      # login: {"error": "...", "error_description": "..."}
            detail = f"{error or ''}: {err.get('error_description') or e.reason}"
        raise TeamsError(f"HTTP {e.code} {detail}") from None
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise TeamsError(str(getattr(e, "reason", e))) from None


class TeamsAuth:
    """Delegated Microsoft Graph tokens from a stored refresh token (device code login)."""

    def __init__(self, path: str | Path = DEFAULT_STATE_DIR / "teams-token.json", login_base: str = LOGIN):
        self.path, self.login_base = Path(path), login_base.rstrip("/")
        self._lock = threading.Lock()
        self._access, self._expires = None, 0.0

    def _load(self) -> dict:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raise TeamsError(f"not signed in to Teams: run `securegent-teams login` first ({self.path})") from None

    def _save(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, self.path)

    def token(self) -> str:
        with self._lock:
            if self._access and time.time() < self._expires - 120:
                return self._access
            saved = self._load()
            got = _request(f"{self.login_base}/{saved['tenant']}/oauth2/v2.0/token", {
                "client_id": saved["client_id"], "grant_type": "refresh_token",
                "refresh_token": saved["refresh_token"], "scope": saved.get("scope", SCOPES)}, form=True)
            if got.get("refresh_token"):                  # refresh tokens rotate
                saved["refresh_token"] = got["refresh_token"]
                self._save(saved)
            self._access, self._expires = got["access_token"], time.time() + int(got.get("expires_in", 3600))
            return self._access

    def login(self, tenant: str, client_id: str, scope: str = SCOPES, out=print) -> None:
        base = f"{self.login_base}/{tenant}/oauth2/v2.0"
        code = _request(f"{base}/devicecode", {"client_id": client_id, "scope": scope}, form=True)
        out(code.get("message") or f"Open {code['verification_uri']} and enter {code['user_code']}")
        deadline = time.time() + int(code.get("expires_in", 900))
        interval = int(code.get("interval", 5))
        while time.time() < deadline:
            time.sleep(interval)
            try:
                got = _request(f"{base}/token", {"client_id": client_id, "device_code": code["device_code"],
                                                 "grant_type": "urn:ietf:params:oauth:grant-type:device_code"}, form=True)
            except TeamsError as e:
                if "authorization_pending" in str(e) or "AADSTS70016" in str(e):
                    continue
                if "slow_down" in str(e):
                    interval += 5
                    continue
                raise
            self._save({"tenant": tenant, "client_id": client_id, "scope": scope,
                        "refresh_token": got["refresh_token"]})
            self._access, self._expires = got["access_token"], time.time() + int(got.get("expires_in", 3600))
            out(f"Signed in. Token saved to {self.path}")
            return
        raise TeamsError("the sign-in code expired; run login again")


class TeamsApproval:
    """An approval channel for FileApprover, like slack.SlackApproval."""

    poll_interval = 4.0

    def __init__(self, auth: TeamsAuth, target: str, approvers: list[str], api_base: str = GRAPH):
        kind, _, rest = target.partition(":")
        if kind == "chat" and rest:
            self.base = f"chats/{urllib.parse.quote(rest, safe='')}/messages"
            self.threaded = False
        elif kind == "channel" and "/" in rest:
            team, channel = rest.split("/", 1)
            self.base = f"teams/{urllib.parse.quote(team, safe='')}/channels/{urllib.parse.quote(channel, safe='')}/messages"
            self.threaded = True
        else:
            raise ValueError("Teams target must be chat:<chat id> or channel:<team id>/<channel id>")
        approvers = [a.strip() for a in approvers if a.strip()]
        if not approvers:
            raise ValueError("Teams approvals need at least one approver (email or user id), "
                             "otherwise anyone in the chat could approve")
        self.auth, self.api_base, self.approvers_raw = auth, api_base.rstrip("/"), approvers
        self._ids: dict[str, str] | None = None

    def _api(self, path: str, data: dict | None = None) -> dict:
        return _request(f"{self.api_base}/{path}", data, token=self.auth.token())

    def _approver_ids(self) -> dict[str, str]:
        """Emails are resolved to Entra object ids once (reactions only carry ids)."""
        if self._ids is None:
            ids = {}
            for a in self.approvers_raw:
                if "@" in a:
                    u = self._api(f"users/{urllib.parse.quote(a)}?$select=id,displayName")
                    ids[u["id"]] = u.get("displayName") or a
                else:
                    ids[a] = a
            self._ids = ids
        return self._ids

    def start(self, request_id: str, request: dict, timeout: float):
        try:
            names = ", ".join(self._approver_ids().values())
            args = json.dumps(request.get("args"), default=str, ensure_ascii=False, indent=1)
            if len(args) > 1500:
                args = args[:1500] + "\n..."
            esc = lambda s: str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            html = (f"<p><b>⚠️ Securegent approval needed</b> ({esc(names)})</p>"
                    f"<p><b>Agent:</b> {esc(request.get('agent', '?'))} acting for {esc(request.get('on_behalf_of', '?'))}<br>"
                    f"<b>Action:</b> <code>{esc(request.get('tool', '?'))}</code><br>"
                    f"<b>Why it needs you:</b> {esc(request.get('reason', ''))}</p>"
                    f"<pre>{esc(args)}</pre>"
                    f"<p>React 👍 to approve or 😠 / 👎 to deny. No answer in {int(timeout)} s means deny. "
                    f"(request {request_id[:8]})</p>")
            msg = self._api(self.base, {"body": {"contentType": "html", "content": html}})
        except TeamsError as e:
            _log(f"Teams approval request not sent ({e}); use the dashboard")
            return None
        return {"id": msg["id"], "short": request_id[:8]}

    def poll(self, handle) -> bool | None:
        try:
            msg = self._api(f"{self.base}/{handle['id']}")
            ids = self._approver_ids()
        except TeamsError as e:
            _log(f"could not read Teams reactions: {e}")
            return None
        approved_by, denied_by = set(), set()
        for r in msg.get("reactions") or []:
            who = ((r.get("user") or {}).get("user") or {}).get("id")
            if who not in ids:
                continue
            kind = r.get("reactionType", "")
            if kind in DENY:
                denied_by.add(ids[who])
            elif kind in APPROVE:
                approved_by.add(ids[who])
        if denied_by:
            handle["by"] = sorted(denied_by)
            return False
        if approved_by:
            handle["by"] = sorted(approved_by)
            return True
        return None

    def finish(self, handle, approved: bool | None, where: str) -> None:
        verdict = "✅ Approved" if approved else "❌ Denied"
        if where == "timeout":
            text = "⌛ Expired: denied (nobody answered in time)"
        elif where == "here":
            text = verdict + " by " + ", ".join(handle.get("by", []))
        elif where == "dashboard":
            text = verdict + " in the dashboard"
        else:
            text = verdict + " in another app"
        text += f" (request {handle['short']})"
        path = f"{self.base}/{handle['id']}/replies" if self.threaded else self.base
        try:
            self._api(path, {"body": {"contentType": "text", "content": text}})
        except TeamsError as e:
            _log(f"could not post the outcome to Teams: {e}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="securegent-teams", description="Set up Microsoft Teams approvals.")
    sub = p.add_subparsers(dest="cmd", required=True)
    lg = sub.add_parser("login", help="sign in once with a device code and store a refresh token")
    lg.add_argument("--tenant", required=True, help="Directory (tenant) id of your organisation")
    lg.add_argument("--client-id", required=True, help="Application (client) id of the app you registered")
    lg.add_argument("--channels", action="store_true", help="also ask for channel permissions (needs an admin)")
    sub.add_parser("chats", help="list your recent chats and their ids")
    sub.add_parser("whoami", help="check the stored sign-in")
    for s in sub.choices.values():
        s.add_argument("--token-file", default=str(DEFAULT_STATE_DIR / "teams-token.json"))
    args = p.parse_args(argv)
    auth = TeamsAuth(args.token_file)
    try:
        if args.cmd == "login":
            auth.login(args.tenant, args.client_id, SCOPES + (" " + CHANNEL_SCOPES if args.channels else ""))
        elif args.cmd == "chats":
            chats = _request(f"{GRAPH}/me/chats?$top=30&$orderby=lastMessagePreview/createdDateTime desc"
                             "&$expand=members", token=auth.token())
            for c in chats.get("value", []):
                who = ", ".join(m.get("displayName") or "?" for m in c.get("members", [])[:4])
                print(f"chat:{c['id']}\n    {c.get('topic') or c.get('chatType')}: {who}")
        elif args.cmd == "whoami":
            me = _request(f"{GRAPH}/me?$select=displayName,userPrincipalName", token=auth.token())
            print(f"Signed in as {me.get('displayName')} <{me.get('userPrincipalName')}>")
    except TeamsError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
