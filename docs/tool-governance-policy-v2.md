# Tool Governance Policy v2

Runtime policy v2 models agent tools as an explicit inventory instead of relying only on generic tool-name matching.

## Profile Fields

Profiles include:

- profile id, name, version, environment, default mode
- agent id, name, environment, default mode
- tool name, action type, risk level, default mode
- argument constraints
- sensitive destination patterns
- unknown tool behavior

Supported action types are `read`, `write`, `export`, `send`, and `admin`.

Supported risk levels are `low`, `medium`, `high`, and `critical`.

Supported modes are `allow`, `block`, and `review`.

Supported environments are `dev`, `staging`, and `production-like`.

## Example

The committed example profile is `docs/examples/runtime/support-agent-profile.json`.

`crm_lookup_order` is read-only and allowed. `billing_refund_customer` is high-risk write behavior and blocked. `export_customer_data` is review-gated for sensitive destinations. `send_customer_email` blocks configured external destinations. Unknown tools fail closed.

## Engine API

```typescript
import {
  DEFAULT_RUNTIME_POLICY_PROFILE,
  evaluateRuntimeToolRequest,
} from '@anticlaude/engine'

const decision = evaluateRuntimeToolRequest(DEFAULT_RUNTIME_POLICY_PROFILE, {
  agentId: 'support-agent',
  toolCall: {
    name: 'export_customer_data',
    arguments: { destination: 'external@example.com' },
  },
})
```

The returned decision includes agent id, tool name, tool action type, risk level, policy id, evidence, and recommended action.

