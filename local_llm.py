"""
Free local backend: runs the agent loop against a model served by Ollama
(http://localhost:11434). No API key, nothing leaves the laptop.

Uses only the Python standard library.
"""

import json
import urllib.error
import urllib.request

OLLAMA_URL = "http://localhost:11434/api/chat"
DEFAULT_MODEL = "qwen2.5:3b"


def _chat(model: str, messages: list, tools: list) -> dict:
    payload = json.dumps({
        "model": model,
        "messages": messages,
        "tools": tools,
        "stream": False,
        "options": {"temperature": 0.2},
    }).encode()
    req = urllib.request.Request(OLLAMA_URL, data=payload,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=600) as resp:
        return json.loads(resp.read())["message"]


def run_local_agent(system: str, user: str, tools: list[dict], handlers: dict,
                    model: str = DEFAULT_MODEL, max_steps: int = 15) -> str:
    """
    tools:    Ollama tool definitions ({"type": "function", "function": {...}})
    handlers: tool name -> python function(**args) -> str
    Returns the model's final text answer.
    """
    messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]

    for _ in range(max_steps):
        try:
            msg = _chat(model, messages, tools)
        except urllib.error.URLError:
            raise SystemExit("\nCan't reach Ollama at localhost:11434. Open the Ollama app "
                             "(or run `ollama serve`) and try again.")
        messages.append(msg)

        calls = msg.get("tool_calls") or []
        if not calls:
            return msg.get("content", "")

        for call in calls:
            name = call["function"]["name"]
            args = call["function"].get("arguments") or {}
            if isinstance(args, str):            # some models send a JSON string
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            fn = handlers.get(name)
            if fn is None:
                result = f"Error: unknown tool '{name}'"
            else:
                try:
                    result = fn(**args)
                except TypeError as e:            # model passed wrong/missing arguments
                    result = f"Error: bad arguments for {name}: {e}"
            messages.append({"role": "tool", "content": str(result), "tool_name": name})

    return "(stopped: reached the step limit)"


def to_ollama_tools(anthropic_tools) -> list[dict]:
    """Convert the SDK @beta_tool definitions into Ollama's tool format."""
    out = []
    for t in anthropic_tools:
        d = t.to_dict()
        out.append({"type": "function", "function": {
            "name": d["name"],
            "description": d.get("description", ""),
            "parameters": d["input_schema"],
        }})
    return out
