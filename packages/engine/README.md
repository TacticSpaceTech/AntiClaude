# @anticlaude/engine

Core library for AntiClaude: agent red-team evals, report comparison, local guard, and runtime policy.

```bash
npm install @anticlaude/engine
```

## Features

- **Attack runner** — bundled payloads with adaptive variant strategies
- **Eval suites** — deterministic selection by seed, category, severity, tags, or ids
- **Detection** — rule-based + global patterns; optional LLM judge
- **Report compare** — baseline/current diff with score, breach, error, and category gates
- **Guard SDK** — local policy evaluator for prompt, tool-call, and output risk
- **Runtime policy** — per-agent tools, risk levels, allow/block/review
- **Audit trace** — redacted JSONL writer/parser and incident index
- **MCP / skill audit** — configuration and definition scanners
- **Target adapters** — generic JSON, OpenAI chat, Anthropic messages, custom templates
- **Fixtures** — local mock agents for eval labs

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
  endpoint: 'https://your-agent.example/api/chat',
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
  toolCall: {
    name: 'export_customer_data',
    arguments: { destination: 'external@example.com' },
  },
})
console.log(runtimeDecision.action)
```

CLI wrapper: [`anticlaude`](https://www.npmjs.com/package/anticlaude)  
Docs: [github.com/TacticSpaceTech/AntiClaude](https://github.com/TacticSpaceTech/AntiClaude)

## License

[AGPL-3.0-only](./LICENSE)
