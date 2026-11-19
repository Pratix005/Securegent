"""Securegent local web dashboard: live audit log, approvals, kill switch."""

from .server import DashboardState, create_server

__all__ = ["DashboardState", "create_server"]
