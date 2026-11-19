"""Agent identities and short-lived, scoped, signed credentials."""

import base64
import hashlib
import hmac
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from fnmatch import fnmatch


class AuthError(Exception):
    """Raised when a token is invalid, expired, revoked or out of scope."""


@dataclass
class Agent:
    agent_id: str
    owner: str                      # the human accountable for this agent
    allowed_scopes: list[str]       # the most this agent may ever be granted
    disabled: bool = False
    revoked_tokens: set[str] = field(default_factory=set)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class AgentRegistry:
    def __init__(self, secret: bytes | None = None):
        self._secret = secret or os.environ.get("AGENTGUARD_SECRET", "").encode() or os.urandom(32)
        self._agents: dict[str, Agent] = {}

    # --- registration -------------------------------------------------
    def register(self, agent_id: str, owner: str, allowed_scopes: list[str]) -> Agent:
        if agent_id in self._agents:
            raise ValueError(f"agent '{agent_id}' already registered")
        agent = Agent(agent_id, owner, list(allowed_scopes))
        self._agents[agent_id] = agent
        return agent

    def get(self, agent_id: str) -> Agent:
        try:
            return self._agents[agent_id]
        except KeyError:
            raise AuthError(f"unknown agent '{agent_id}'") from None

    # --- credentials --------------------------------------------------
    def issue_token(self, agent_id: str, scopes: list[str], ttl_seconds: int = 300,
                    on_behalf_of: str | None = None, task: str | None = None) -> str:
        """Issue a task-scoped token. Scopes must be within the agent's allowed scopes."""
        agent = self.get(agent_id)
        if agent.disabled:
            raise AuthError(f"agent '{agent_id}' is disabled")
        for scope in scopes:
            if not any(fnmatch(scope, allowed) for allowed in agent.allowed_scopes):
                raise AuthError(f"scope '{scope}' exceeds what '{agent_id}' may be granted")
        claims = {
            "jti": uuid.uuid4().hex,
            "sub": agent_id,
            "owner": agent.owner,
            "on_behalf_of": on_behalf_of or agent.owner,
            "task": task,
            "scopes": scopes,
            "iat": int(time.time()),
            "exp": int(time.time()) + ttl_seconds,
        }
        body = _b64(json.dumps(claims, separators=(",", ":")).encode())
        sig = _b64(hmac.new(self._secret, body.encode(), hashlib.sha256).digest())
        return f"{body}.{sig}"

    def verify(self, token: str) -> dict:
        try:
            body, sig = token.split(".")
        except ValueError:
            raise AuthError("malformed token") from None
        expected = _b64(hmac.new(self._secret, body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            raise AuthError("bad signature")
        claims = json.loads(_unb64(body))
        agent = self.get(claims["sub"])
        if agent.disabled:
            raise AuthError(f"agent '{agent.agent_id}' is disabled (kill switch)")
        if claims["jti"] in agent.revoked_tokens:
            raise AuthError("token revoked")
        if time.time() > claims["exp"]:
            raise AuthError("token expired")
        return claims

    @staticmethod
    def has_scope(claims: dict, tool: str) -> bool:
        return any(fnmatch(tool, scope) for scope in claims["scopes"])

    # --- kill switch --------------------------------------------------
    def revoke_token(self, token: str) -> None:
        claims = json.loads(_unb64(token.split(".")[0]))
        self.get(claims["sub"]).revoked_tokens.add(claims["jti"])

    def disable(self, agent_id: str) -> None:
        """Kill switch: every token for this agent stops working immediately."""
        self.get(agent_id).disabled = True

    def enable(self, agent_id: str) -> None:
        self.get(agent_id).disabled = False
