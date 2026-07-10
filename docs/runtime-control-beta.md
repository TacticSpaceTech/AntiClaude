# Runtime Control Beta

AntiClaude Runtime Control Beta is a local workflow for tool-using agents. It combines:

- a deterministic `support-agent` fixture
- runtime tool-governance profiles
- local Guard gateway evaluation
- JSONL human review storage
- redacted trace replay and incident indexing
- `/control-plane` example inspection

It is not a hosted service, team dashboard, billing product, compliance certification tool, or production runtime firewall.

## Local Flow

```bash
pnpm run build:engine
pnpm run build:cli

node packages/cli/dist/index.js fixtures --kind support-agent --port 4100

node packages/cli/dist/index.js guard \
  --target http://127.0.0.1:4100/chat \
  --review-store /tmp/anticlaude-reviews.jsonl \
  --trace /tmp/anticlaude-runtime.jsonl
```

Requests that produce safe read-only tool calls are forwarded. Requests that produce blocked tool calls return `403`. Requests that need human review return `202` and a `reviewId`.

## Example Data

- Runtime profile: `docs/examples/runtime/support-agent-profile.json`
- Review queue: `docs/examples/runtime/review-queue.json`
- Runtime incident trace: `docs/examples/traces/runtime-incident.jsonl`

## Main Surfaces

- Engine: `packages/engine/src/runtime-policy.ts`
- Review storage: `packages/engine/src/review-queue.ts`
- Incident index: `packages/engine/src/incident-store.ts`
- Gateway integration: `packages/engine/src/guard-gateway.ts`
- CLI review command: `packages/cli/src/commands/review.ts`
- Web console: `app/control-plane/page.tsx`

