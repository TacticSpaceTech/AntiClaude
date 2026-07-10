# @anticlaude/engine

Core scanning engine for AntiClaude.

## Features

- **Attack Runner** — 64 bundled payloads with adaptive variant strategies
- **Eval Suites** — deterministic payload selection by seed, category, severity, tags, or ids
- **Detection Engine** — Rule-based + global pattern detection with confidence scoring
- **Report Compare** — baseline/current diffing with score, breach, error, confidence, and category gates
- **LLM Judge** — Optional semantic detection via OpenAI/Anthropic APIs
- **Guard SDK** — local policy evaluator for prompt, tool-call, and output risk
- **Runtime Policy** — per-agent tool inventory, risk levels, allow/block/review decisions, and local review records
- **Audit Trace** — redacted JSONL trace writer/parser and replay summaries
- **Incident Store** — local trace index for trace/request/agent/policy/action/tool queries
- **MCP Scanner** — Audit MCP server configurations for security issues
- **Skill Auditor** — Static analysis of tool/skill definitions (6 dimensions)
- **Reporter** — JSON, Markdown, and HTML report generation
- **Target Adapters** — Generic JSON, OpenAI-compatible chat, Anthropic-compatible messages, and custom JSON body templates

## Usage

```typescript
import {
  DEFAULT_GUARD_POLICY,
  DEFAULT_RUNTIME_POLICY_PROFILE,
  evaluateGuardPolicy,
  evaluateRuntimeToolRequest,
  runScan,
} from '@anticlaude/engine'

const report = await runScan({
  endpoint: 'https://your-agent.com/api/chat',
  target: {
    adapter: 'generic-json',
    bodyField: 'message',
  },
  payloadCount: 10,
})

console.log(`Report contract: v${report.reportVersion}`)
console.log(`Score: ${report.score}/100`)

const decision = evaluateGuardPolicy(DEFAULT_GUARD_POLICY, {
  surface: 'tool-call',
  toolCall: { name: 'refund_user', arguments: { amount: 9999 } },
})

console.log(decision.action)

const runtimeDecision = evaluateRuntimeToolRequest(DEFAULT_RUNTIME_POLICY_PROFILE, {
  agentId: 'support-agent',
  toolCall: { name: 'export_customer_data', arguments: { destination: 'external@example.com' } },
})

console.log(runtimeDecision.action)
```

See the [main repository](https://github.com/TacticSpaceTech/AntiClaude) for full documentation.

## License

[AGPL-3.0-only](../../LICENSE)
