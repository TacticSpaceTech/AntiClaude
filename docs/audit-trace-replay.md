# Audit Trace And Replay

AntiClaude trace files are local JSONL artifacts. They explain the timeline from incoming prompt to policy decision, forwarding, response evaluation, and final block/review/allow result.

## Event Contract

Each event has:

- `traceVersion: 1`
- `id`
- `traceId`
- `requestId`
- `timestamp`
- `type`
- optional `surface`, `target`, `prompt`, `request`, `response`, `toolCall`, `decision`, `redactions`, and `durationMs`

Event types:

- `request`
- `policy-decision`
- `forwarded-request`
- `target-response`
- `blocked-response`
- `review-response`
- `error`

## Redaction

Trace writing redacts sensitive key names and common secret value patterns:

- `Authorization`
- API keys
- tokens
- cookies
- passwords
- bearer tokens

The trace event records redaction metadata as `{ path, reason }`.

## Replay

```bash
node packages/cli/dist/index.js replay docs/examples/traces/sample-trace.jsonl
```

Use JSON output for automation:

```bash
node packages/cli/dist/index.js replay docs/examples/traces/sample-trace.jsonl --output json
```
