# anticlaude

CLI for AI agent security testing.

## Commands

- `anticlaude scan` — Red-team an agent endpoint for prompt injection and OWASP vulnerabilities
- `anticlaude fixtures` — Start deterministic local mock agents for evals
- `anticlaude compare` — Compare baseline and current JSON reports with regression gates
- `anticlaude audit` — Static analysis of skill/tool definitions
- `anticlaude mcp-scan` — Discover and audit MCP server configurations
- `anticlaude badge` — Generate a security badge for your README
- `anticlaude guard` — Start the local-only Guard alpha gateway
- `anticlaude replay` — Replay local JSONL audit traces
- `anticlaude review` — List, show, approve, or deny local runtime review requests

## Quick Start

```bash
npx anticlaude scan \
  --endpoint https://your-agent.com/api/chat \
  --adapter generic-json \
  --body-field message \
  --suite docs/examples/suites/phase2-smoke-suite.json
```

```bash
npx anticlaude compare baseline.json current.json \
  --fail-on-new-severity critical,high \
  --fail-on-category-regression
```

```bash
npx anticlaude replay docs/examples/traces/sample-trace.jsonl
```

```bash
node packages/cli/dist/index.js review list --store /tmp/anticlaude-reviews.jsonl
```

See the [main repository](https://github.com/TacticSpaceTech/AntiClaude) for full documentation.

## License

[AGPL-3.0-only](../../LICENSE)
