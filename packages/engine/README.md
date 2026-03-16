# @anticlaude/engine

Core scanning engine for AntiClaude.

## Features

- **Attack Runner** — 64 bundled payloads with adaptive variant strategies
- **Detection Engine** — Rule-based + global pattern detection with confidence scoring
- **LLM Judge** — Optional semantic detection via OpenAI/Anthropic APIs
- **MCP Scanner** — Audit MCP server configurations for security issues
- **Skill Auditor** — Static analysis of tool/skill definitions (6 dimensions)
- **Reporter** — JSON, Markdown, and HTML report generation

## Usage

```typescript
import { runScan } from '@anticlaude/engine'

const report = await runScan({
  endpoint: 'https://your-agent.com/api/chat',
  payloadCount: 10,
})

console.log(`Score: ${report.score}/100`)
```

See the [main repository](https://github.com/TacticSpaceTech/AntiClaude) for full documentation.
