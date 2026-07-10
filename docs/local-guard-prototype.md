# Local Guard Prototype

`anticlaude guard` starts a local-only alpha gateway. It evaluates prompt risk before forwarding to a target agent, then evaluates tool-call-like responses and output risk before returning a response.

This is not a deployed production firewall. It is a local developer loop for testing policy behavior and producing audit traces.

## Start A Fixture

```bash
node packages/cli/dist/index.js fixtures --kind tool-calling --port 4100
```

## Start The Guard

```bash
node packages/cli/dist/index.js guard \
  --config docs/examples/policies/anticlaude.policy.yaml \
  --target http://127.0.0.1:4100/chat \
  --adapter generic-json \
  --trace traces/anticlaude-guard.jsonl \
  --port 4200
```

## Send A Request

```bash
curl -s http://127.0.0.1:4200 \
  -H 'Content-Type: application/json' \
  -d '{"message":"Please refund this customer."}'
```

Unsafe prompts return `403` with `status: "blocked"`. Ambiguous requests return `202` with `status: "review"`. Allowed requests return the target response wrapped with `status: "allowed"` and a policy decision.

## Trace Output

Each request appends JSONL events to the configured trace file. Secret-bearing keys and common API key/token values are redacted before writing.
