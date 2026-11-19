"""LLM backends that run a tool-calling agent loop.

Each backend exposes run_agent(system, user, tools, handlers, model, max_steps) -> str
and a DEFAULT_MODEL.
"""

import importlib


def get_backend(name: str):
    if name not in ("ollama", "claude"):
        raise ValueError(f"unknown backend '{name}' (choose: ollama, claude)")
    return importlib.import_module(f"{__name__}.{name}")
