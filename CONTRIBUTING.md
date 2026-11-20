# Contributing to Securegent

Thanks for helping make AI agents safer! All contributions are welcome: code, policy
rules, attack scenarios, docs and bug reports.

## Getting started

```
git clone <your fork>
cd securegent
python -m venv .venv
.venv\Scripts\activate          # Windows  (macOS/Linux: source .venv/bin/activate)
pip install -e ".[claude]"
python -m unittest discover tests -v
python demo.py
```

## Ways to help

- **Attack scenarios (easiest, no Python needed):** write a prompt-injection attack as a JSON
  file in `attacks/`. Copy `attacks/TEMPLATE.json`, follow [attacks/README.md](attacks/README.md),
  and check it with `securegent-redteam --scenarios attacks/`. Prefer not to write JSON? Open
  a "New attack scenario" issue and describe it.
- **Policy packs:** ready-made rule sets for an industry or an MCP server, in
  `securegent/packs/`, with tests in `tests/` (see `tests/test_more_packs.py`).
- **Integrations:** OpenAI, LangChain, LlamaIndex, MCP servers.
- **Docs and examples.**

Look for issues labelled `good first issue`.

## Pull request checklist

1. One focused change per PR.
2. Add or update tests in `tests/`, and make sure all tests pass.
3. Keep the core (`securegent/`) free of third-party dependencies.
4. Explain *why* in the PR description, not only what.

## Reporting security problems

Please don't open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).
