# Runtime Regression Checks

Runtime Control Beta is covered by focused engine tests plus full repo verification.

## Focused Tests

```bash
pnpm --filter @anticlaude/engine run test
```

Relevant files:

- `packages/engine/src/__tests__/support-agent-fixture.test.ts`
- `packages/engine/src/__tests__/runtime-policy.test.ts`
- `packages/engine/src/__tests__/review-queue.test.ts`
- `packages/engine/src/__tests__/guard-gateway.test.ts`
- `packages/engine/src/__tests__/incident-store.test.ts`

These prove safe read allow, unsafe write block, export review, external send block, unknown tool fail-closed, review queue decisions, gateway 202/403 behavior, and incident querying.

## Full Verification

```bash
pnpm run validate:payloads
pnpm run test
pnpm run build
pnpm run build:cli
git diff --check
```

CLI smoke checks:

```bash
node packages/cli/dist/index.js --help
node packages/cli/dist/index.js guard --help
node packages/cli/dist/index.js review --help
node packages/cli/dist/index.js replay docs/examples/traces/sample-trace.jsonl
```

