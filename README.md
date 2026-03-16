<p align="center">
  <h1 align="center">AntiClaude</h1>
  <p align="center">
    <strong>Open-source red-teaming toolkit for AI agents</strong>
  </p>
  <p align="center">
    Detect prompt injection, system prompt leakage, permission abuse, and other
    <a href="https://owasp.org/www-project-agentic-ai-threats/">OWASP Agentic Top 10</a>
    vulnerabilities — from your terminal or CI pipeline.
  </p>
  <p align="center">
    <a href="https://github.com/TacticSpaceTech/AntiClaude/actions/workflows/ci.yml"><img src="https://github.com/TacticSpaceTech/AntiClaude/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
    <a href="https://www.npmjs.com/package/anticlaude"><img src="https://img.shields.io/npm/v/anticlaude" alt="npm"></a>
    <a href="https://www.npmjs.com/package/@anticlaude/engine"><img src="https://img.shields.io/npm/v/@anticlaude/engine" alt="npm engine"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPL--3.0-blue.svg" alt="License: AGPL-3.0"></a>
  </p>
</p>

---

## Why AntiClaude?

- **npm-native** — `npx anticlaude scan` works instantly, no Python or Docker needed
- **64 attack payloads** — covering 7 of 10 OWASP Agentic Top 10 categories
- **Adaptive strategies** — 8 attack mutation strategies (encoding, roleplay, multilingual, nested, semantic, and more)
- **LLM Judge** — optional semantic detection via OpenAI or Anthropic APIs for higher accuracy
- **MCP Scanner** — auto-discover and audit MCP server configs for credential leaks, command injection, and supply chain risks
- **CI-ready** — GitHub Action with PR commenting, fail thresholds, and machine-readable output

## Quick Start

```bash
npx anticlaude scan --endpoint https://your-agent.com/api/chat
```

<details>
<summary>All CLI options</summary>

```
--auth <header>          Authorization header (e.g. "Bearer sk-...")
--count <n>              Number of payloads to test (default: 12)
--variants <n>           Max variant attempts per payload (default: 2)
--timeout <ms>           Request timeout in ms (default: 15000)
--output <format>        Report format: json | markdown | html (default: markdown)
--out <file>             Write report to file
--llm-judge <provider>   Enable LLM judge: openai or anthropic
--llm-key <key>          API key for LLM judge
--json-summary           Output machine-readable summary for CI
```

</details>

## Commands

### Scan — Red-team an agent endpoint

```bash
npx anticlaude scan --endpoint https://your-agent.com/api/chat --auth "Bearer sk-..."
```

### Audit — Static analysis of skill/tool definitions

```bash
npx anticlaude audit path/to/skill.yaml
```

### MCP Scan — Discover and audit MCP server configs

```bash
npx anticlaude mcp-scan
```

Auto-discovers configs from `~/.cursor/mcp.json`, `~/.claude/claude_desktop_config.json`, and project-level paths.

### Badge — Generate a security badge

```bash
npx anticlaude badge --score 85
# ![AntiClaude Security](https://img.shields.io/badge/AntiClaude-85%2F100-brightgreen)
```

## OWASP Agentic Top 10 Coverage

| ID | Category | Payloads | Status |
|----|----------|----------|--------|
| ASI01 | Agent Goal Hijacking | 12 | Covered |
| ASI02 | Tool Misuse & Injection | 12 | Covered |
| ASI03 | Permission Abuse & Escalation | 8 | Covered |
| ASI04 | Supply Chain Vulnerabilities | 8 | Covered |
| ASI05 | Unsafe Code Execution | 8 | Covered |
| ASI06 | Memory Poisoning | — | Planned |
| ASI07 | System Prompt Leakage | 8 | Covered |
| ASI08 | Human-Agent Trust Manipulation | 8 | Covered |
| ASI09 | Uncontrolled Resource Loops | — | Planned |
| ASI10 | Rogue Agent Behavior | — | Planned |

## GitHub Action

```yaml
- uses: TacticSpaceTech/AntiClaude/action@v1
  with:
    endpoint: ${{ secrets.AGENT_ENDPOINT }}
    auth: 'Bearer ${{ secrets.AGENT_TOKEN }}'
    fail-threshold: 70
```

Posts scan results as PR comments and fails the check if the score is below your threshold.

## Using the Engine as a Library

```bash
npm install @anticlaude/engine
```

```typescript
import { runScan } from '@anticlaude/engine'

const report = await runScan({
  endpoint: 'https://your-agent.com/api/chat',
  payloadCount: 10,
})

console.log(`Score: ${report.score}/100`)
console.log(`Breaches: ${report.summary.breaches}`)
```

## Project Structure

```
AntiClaude/
├── packages/
│   ├── engine/       @anticlaude/engine — scanning engine, detection, LLM judge, MCP scanner
│   └── cli/          anticlaude — CLI with scan, audit, mcp-scan, badge commands
├── payloads/         64 YAML attack payloads across 7 OWASP categories
├── action/           GitHub Action for CI integration
└── scripts/          Build and validation tooling
```

## Development

```bash
git clone https://github.com/TacticSpaceTech/AntiClaude.git
cd AntiClaude
pnpm install
pnpm run build          # Build everything
pnpm run test           # Run 61 tests
```

## Contributing

We welcome payload contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for the YAML template, naming conventions, and detection rule guide.

## License

[AGPL-3.0](LICENSE) — Free to use, modify, and distribute. If you run a modified version as a network service, you must open-source your changes.
