"""Securegent red-team suite: prompt-injection attacks against AI agents, with a score."""

from .runner import BLOCKED, COMPROMISED, ERROR, RESISTED, run_agent, run_policy, score
from .scenarios import SCENARIOS, Scenario

__all__ = ["SCENARIOS", "Scenario", "run_agent", "run_policy", "score",
           "RESISTED", "BLOCKED", "COMPROMISED", "ERROR"]
