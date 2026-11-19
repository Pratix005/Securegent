"""
Free local backend: runs an agent loop against a model served by Ollama
(http://localhost:11434). No API key, nothing leaves the machine.

Uses only the Python standard library.

Tools are given in a generic format:
    {"name": str, "description": str, "parameters": <JSON schema>}
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


def run_agent(system: str, user: str, tools: list[dict], handlers: dict,
              model: str = DEFAULT_MODEL, max_steps: int = 15) -> str:
    """Run the tool-calling loop. handlers maps tool name -> fn(**args) -> str."""
    ollama_tools = [{"type": "function", "function": {
        "name": t["name"], "description": t["description"], "parameters": t["parameters"],
    }} for t in tools]
    messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]

    for _ in range(max_steps):
        try:
            msg = _chat(model, messages, ollama_tools)
        except urllib.error.URLError:
            raise RuntimeError("Can't reach Ollama at localhost:11434. Open the Ollama app "
                               "(or run `ollama serve`) and try again.") from None
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
