# AntiClaude

**Red-team your AI agents from the terminal.**

[![CI](https://github.com/MJYKIM99/AntiClaude/actions/workflows/ci.yml/badge.svg)](https://github.com/MJYKIM99/AntiClaude/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/anticlaude)](https://www.npmjs.com/package/anticlaude)
[![npm](https://img.shields.io/npm/v/@anticlaude/engine)](https://www.npmjs.com/package/@anticlaude/engine)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Open-source security scanner for AI agents. Detect prompt injection, system prompt leakage, tool abuse, and other [OWASP Agentic Top 10](https://owasp.org/www-project-agentic-ai-threats/) vulnerabilities — all from your terminal or CI pipeline.

<!-- TODO: Add demo GIF here -->

## Quick Start

### CLI

```bash
npx anticlaude scan --endpoint https://your-agent.com/api/chat
```

Options:

```
--auth <header>     Authorization header (e.g. "Bearer sk-...")
--count <n>         Number of payloads to test (default: 12)
--variants <n>      Max variant attempts per payload (default: 2)
--timeout <ms>      Request timeout in ms (default: 15000)
--output <format>   Report format: json | markdown | html (default: markdown)
--out <file>        Write report to file
```

### Skill Audit

```bash
npx anticlaude audit --skill path/to/skill.yaml
```

Static analysis of AI agent skill/tool definitions for description poisoning, parameter injection, permission scope issues, and more.

### Web UI

```bash
git clone https://github.com/MJYKIM99/AntiClaude.git
cd AntiClaude
pnpm install
pnpm run build:payloads
pnpm dev
```

Open [http://localhost:3000](http://localhost:3000) for the interactive scanner with real-time attack visualization.

## What It Tests

| ID | Category | Payloads |
|----|----------|----------|
| ASI01 | Agent Goal Hijacking | 12 |
| ASI02 | Tool Misuse & Injection | 12 |
| ASI04 | Supply Chain Vulnerabilities | 10 |
| ASI07 | System Prompt Leakage | 8 |
| ASI08 | Human-Agent Trust Manipulation | 8 |

48 YAML-based attack payloads with 8 adaptive strategies: direct, encoding, roleplay, multilingual, nested, semantic, continuation, and fragmented.

## Project Structure

```
AntiClaude/
├── packages/
│   ├── engine/          @anticlaude/engine — core scanning engine
│   └── cli/             anticlaude — CLI tool
├── app/                 Next.js web UI
├── payloads/            48 YAML attack payloads
├── components/          React components
└── lib/                 Shared utilities
```

## Development

```bash
pnpm install
pnpm run build:payloads    # Compile YAML payloads → JSON
pnpm run build:engine      # Build the engine package
pnpm run build:cli         # Build the CLI package
pnpm run test              # Run all tests
pnpm dev                   # Start Next.js dev server
```

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

## Contributing

1. Fork the repo
2. Add payloads in `payloads/` following existing YAML format
3. Run `pnpm run build:payloads && pnpm run test`
4. Submit a PR

## License

[MIT](LICENSE)
