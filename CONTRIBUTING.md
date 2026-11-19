# Contributing to AgentGuard

Thanks for helping make AI agents safer! All contributions are welcome: code, policy
rules, attack scenarios, docs and bug reports.

## Getting started

```
git clone <your fork>
cd agentguard
python -m venv .venv
.venv\Scripts\activate          # Windows  (macOS/Linux: source .venv/bin/activate)
pip install -e ".[claude]"
python -m unittest discover tests -v
python demo.py
```

## Ways to help

- **Policy packs:** ready-made rule sets for an industry (banking, healthcare, HR, DevOps).
- **Attack scenarios:** new prompt-injection cases the guard should stop.
- **Integrations:** OpenAI, LangChain, LlamaIndex, MCP servers.
- **Docs and examples.**

Look for issues labelled `good first issue`.

## Pull request checklist

1. One focused change per PR.
2. Add or update tests in `tests/`, and make sure all tests pass.
3. Keep the core (`agentguard/`) free of third-party dependencies.
4. Explain *why* in the PR description, not only what.

## Reporting security problems

Please don't open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).
