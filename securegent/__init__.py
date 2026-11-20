"""Securegent: identity, permissions and audit for AI agents."""

from .guard import AuditLog, Blocked, Guard
from .identity import AgentRegistry, AuthError
from .policy import Policy

__all__ = ["AgentRegistry", "AuthError", "AuditLog", "Blocked", "Guard", "Policy"]
__version__ = "0.3.0"
