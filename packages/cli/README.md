# anticlaude

CLI for AI agent security evals, CI regression gates, and local runtime control.

```bash
npm install -g anticlaude
# or
npx anticlaude@1.1.0 --help
```

## Commands

| Command | Purpose |
| --- | --- |
| `scan` | Red-team an agent endpoint |
| `fixtures` | Start deterministic local mock agents |
| `compare` | Baseline vs current report + regression gates |
| `audit` | Static analysis of skill/tool definitions |
| `mcp-scan` | Discover and audit MCP server configs |
| `badge` | Generate a shields.io badge URL |
| `guard` | Local-only Guard alpha gateway |
| `replay` | Replay local JSONL audit traces |
| `review` | List / show / approve / deny runtime reviews |

## Built-in examples (shipped in the npm package)

| Kind | Names | Use |
| --- | --- | --- |
| Suite | `smoke`, `builtin:smoke` | `scan --suite smoke` |
| Policy | `default`, `builtin:default` | `guard --config default` |

Filesystem paths still work (`--suite ./my-suite.json`).

## Quick start

```bash
npx anticlaude@1.1.0 fixtures --kind vulnerable-generic --port 4100

npx anticlaude@1.1.0 scan \
  --endpoint http://127.0.0.1:4100/chat \
  --suite smoke \
  --adapter generic-json \
  --output json \
  --out current.json

npx anticlaude@1.1.0 compare baseline.json current.json \
  --fail-on-new-severity critical,high \
  --fail-on-category-regression
```

```bash
npx anticlaude@1.1.0 guard --config default --target http://127.0.0.1:4100/chat
npx anticlaude@1.1.0 replay path/to/trace.jsonl
```

`guard` and `review` are local-only beta tools, not a production firewall.

Full documentation: [github.com/TacticSpaceTech/AntiClaude](https://github.com/TacticSpaceTech/AntiClaude)

## License

[AGPL-3.0-only](./LICENSE)
