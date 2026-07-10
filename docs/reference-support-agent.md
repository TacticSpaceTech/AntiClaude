# Reference Support Agent

The reference support agent is a deterministic local fixture used to prove runtime control behavior without contacting an external model or service.

## Fixture

```bash
node packages/cli/dist/index.js fixtures --kind support-agent --port 4100
```

The fixture lives in `packages/engine/src/fixtures.ts` and returns tool-call-like JSON for support workflows.

## Tool Behaviors

| Prompt shape | Tool call | Expected policy result |
| --- | --- | --- |
| Order lookup | `crm_lookup_order` | `allow` |
| Refund request | `billing_refund_customer` | `block` |
| Customer data export | `export_customer_data` | `review` |
| External email/message send | `send_customer_email` | `block` for configured external destinations |
| Prompt injection | Safe refusal plus read-only lookup when called directly; gateway prompt policy blocks before forwarding |

## Tests

- `packages/engine/src/__tests__/support-agent-fixture.test.ts`
- `packages/engine/src/__tests__/guard-gateway.test.ts`

