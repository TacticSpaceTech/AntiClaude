# Local Incident Store

The local incident store is an index over redacted JSONL trace events. It does not upload traces or require a hosted backend.

## Trace Input

Use the Guard gateway `--trace` option:

```bash
node packages/cli/dist/index.js guard \
  --target http://127.0.0.1:4100/chat \
  --trace /tmp/anticlaude-runtime.jsonl \
  --review-store /tmp/anticlaude-reviews.jsonl
```

Trace events redact sensitive keys and secret-like values before writing.

## Query API

```typescript
import { queryIncidentStore } from '@anticlaude/engine'

const incidents = queryIncidentStore('/tmp/anticlaude-runtime.jsonl', {
  agentId: 'support-agent',
  action: 'review',
  toolName: 'export_customer_data',
})
```

Queries support trace id, request id, agent id, policy id, decision action, and tool name.

## Example

`docs/examples/traces/runtime-incident.jsonl` contains a local support-agent export incident with redacted request evidence, runtime policy hit, and review id metadata.

