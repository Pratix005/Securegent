"""
Claude backend: runs an agent loop on the Claude API. Needs `pip install securegent[claude]`
and an API key (ANTHROPIC_API_KEY).

Tools are given in a generic format:
    {"name": str, "description": str, "parameters": <JSON schema>}
"""

DEFAULT_MODEL = "claude-opus-5-5"


def run_agent(system: str, user: str, tools: list[dict], handlers: dict,
              model: str = DEFAULT_MODEL, max_steps: int = 15) -> str:
    """Run the tool-calling loop. handlers maps tool name -> fn(**args) -> str."""
    import anthropic

    client = anthropic.Anthropic()
    api_tools = [{"name": t["name"], "description": t["description"],
                  "input_schema": t["parameters"]} for t in tools]
    messages = [{"role": "user", "content": user}]

    for _ in range(max_steps):
        response = client.beta.messages.create(
            model=model,
            max_tokens=16000,
            system=system,
            tools=api_tools,
            messages=messages,
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        )
        if response.stop_reason == "refusal":
            return "(model declined the task)"

        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason == "pause_turn":
            continue
        if response.stop_reason != "tool_use":
            return "\n".join(b.text for b in response.content if b.type == "text")

        results = []
        for block in response.content:
            if block.type != "tool_use":
                continue
            fn = handlers.get(block.name)
            is_error = False
            if fn is None:
                out, is_error = f"Error: unknown tool '{block.name}'", True
            else:
                try:
                    out = fn(**block.input)
                except TypeError as e:
                    out, is_error = f"Error: bad arguments for {block.name}: {e}", True
            result = {"type": "tool_result", "tool_use_id": block.id, "content": str(out)}
            if is_error:
                result["is_error"] = True
            results.append(result)
        # all results for this turn go back in one user message
        messages.append({"role": "user", "content": results})

    return "(stopped: reached the step limit)"
