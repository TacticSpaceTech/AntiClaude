# AntiClaude Phase 3 Long-Horizon Goal: Runtime Control Beta

## Phase 3 Name

**Runtime Control Beta: Tool Governance + Human Review + Incident Console**

## Primary Objective

Turn the Phase 2 local control-plane alpha into a design-partner-ready runtime control beta for tool-using agents.

The finished phase must prove this workflow locally:

1. Start a reference tool-using support agent.
2. Attach AntiClaude Guard to the agent runtime.
3. Configure per-agent and per-tool policy.
4. Allow safe read-only tool calls.
5. Block unsafe tool calls.
6. Route ambiguous or high-impact actions to human review.
7. Approve or deny a queued review decision.
8. Persist the full incident trace with redaction.
9. Inspect agents, tools, reviews, policy hits, and incident replay in Web.
10. Run CI/local checks that prove policy changes do not regress behavior.

## Why This Goal Is Bigger

Phase 2 proved the local eval/control-plane alpha:

- deterministic eval suites
- baseline comparison
- report schema v1
- Guard SDK foundation
- local Guard alpha gateway
- JSONL trace/replay
- local Web inspection
- Action compare gates

Phase 3 should not jump straight to hosted SaaS, billing, or compliance. The core product risk is still whether AntiClaude can control a real tool-using agent workflow with enough evidence and review ergonomics for design partners.

## Product North Star

AntiClaude should help a JS/TS team answer:

1. Which agents and tools are protected?
2. Which tool actions are safe, blocked, or review-gated?
3. Who approved a risky action, why, and when?
4. Can we replay the exact evidence behind an incident?
5. Did a policy change improve safety without breaking safe workflows?

## Acceptance Criteria

### 1. Reference Tool-Using Agent

- Add a deterministic local support-agent fixture.
- It must expose tool-call-like behavior for:
  - read-only CRM/order lookup
  - billing refund/write action
  - customer data export
  - external email/message send
- Add tests proving:
  - safe read-only request produces a read tool call
  - refund/export/send requests produce high-risk tool calls
  - prompt injection still exercises prompt policy

### 2. Tool Governance Policy v2

- Add a runtime policy/profile model for:
  - agent id/name
  - tool inventory
  - tool action type: `read`, `write`, `export`, `send`, `admin`
  - risk level: `low`, `medium`, `high`, `critical`
  - default mode: `allow`, `block`, `review`
  - env profile: `dev`, `staging`, `production-like`
  - argument constraints
  - sensitive destination patterns
- Add policy validation and tests.
- Preserve existing Guard SDK behavior.

### 3. Runtime Decision Engine

- Evaluate tool execution requests against the runtime policy/profile.
- Return `allow`, `block`, or `review`.
- Decision evidence must include:
  - agent id
  - tool name
  - tool action type
  - risk level
  - matched rule/policy id
  - matched arguments/evidence
  - recommended action
- Add focused tests:
  - safe read allowed
  - unsafe write blocked
  - data export review-gated
  - external send review-gated or blocked by destination
  - unknown tool fails closed

### 4. Human Review Queue

- Add local review queue storage.
- A review request must include:
  - review id
  - request id
  - trace id
  - agent id
  - tool call
  - policy decision
  - evidence
  - status: `pending`, `approved`, `denied`, `expired`
  - timestamps
- Add CLI review commands:
  - list pending reviews
  - show a review
  - approve a review with reason
  - deny a review with reason
- Add tests for create/list/approve/deny behavior.

### 5. Gateway v2 Review Integration

- Extend the local Guard gateway to optionally write review requests.
- Review responses must return explicit `202` with review id.
- Blocked responses must remain explicit `403`.
- Allowed responses must continue to forward safely.
- Add tests against local fixtures.

### 6. Local Incident Store

- Add a structured local incident store or trace index.
- It must query by:
  - trace id
  - request id
  - agent id
  - policy id
  - decision action
  - tool name
- Add tests for redaction and query parsing.

### 7. Web Runtime Console

- Upgrade `/control-plane` from static Phase 2 examples into a local runtime beta console surface.
- Add sections for:
  - agent inventory
  - tool inventory
  - policy profile summary
  - review queue
  - incident timeline/replay
  - policy hit details
- It may use committed example data, but must be clearly local/example based.
- It must not imply hosted dashboards, team accounts, billing, compliance readiness, or production firewall deployment.

### 8. CI Regression Coverage

- Add local regression fixtures for runtime policy behavior.
- Add tests or scripts proving:
  - safe tool call remains allowed
  - unsafe write remains blocked
  - export/send review behavior remains stable
  - unknown tool fails closed
- Keep existing scan/report/compare Action behavior stable.

### 9. Documentation

- Add docs for:
  - runtime control beta workflow
  - reference support-agent fixture
  - tool governance policy v2
  - human review workflow
  - local incident store
  - Web runtime console
  - CI/runtime regression checks
- Update public copy to describe shipped local runtime beta only.

### 10. Security And Product Boundaries

- No hosted SaaS dashboard.
- No team accounts.
- No billing.
- No public marketplace.
- No compliance certification claims.
- No production deployment promise.
- No external target scans without explicit user approval.
- No publishing, deployment, push, tag, or release without explicit user approval.

## Work Slices

1. Repo audit and Phase 3 ledger.
2. Reference support-agent fixture.
3. Tool governance policy/profile v2.
4. Runtime decision engine.
5. Human review queue.
6. Gateway review integration.
7. Local incident store.
8. Web runtime console.
9. CI/runtime regression coverage.
10. Docs truth reset.
11. Full verification and completion audit.

## Required Verification

Before completion, run:

```bash
pnpm run validate:payloads
pnpm run test
pnpm run build
pnpm run build:cli
git diff --check
git status --short
```

Also run targeted smoke checks:

```bash
node packages/cli/dist/index.js --help
node packages/cli/dist/index.js guard --help
node packages/cli/dist/index.js review --help
node packages/cli/dist/index.js replay docs/examples/traces/sample-trace.jsonl
```

Run local runtime checks:

```bash
# Exact ports may differ.
node packages/cli/dist/index.js fixtures --kind support-agent --port 4100
node packages/cli/dist/index.js guard --target http://127.0.0.1:4100/chat --review-store /tmp/anticlaude-reviews.jsonl --trace /tmp/anticlaude-runtime.jsonl
node packages/cli/dist/index.js review list --store /tmp/anticlaude-reviews.jsonl
```

Run Web/manual checks:

- Start local dev server.
- Confirm `/control-plane` renders runtime beta sections.
- Confirm Web/API route protections from Phase 2 still fail closed.
- Confirm real scan mode does not emit simulated findings.

## Completion Audit Requirements

Before marking complete:

- Build a prompt-to-artifact checklist.
- Map every acceptance criterion to concrete files, tests, commands, and observed outputs.
- Re-read changed public copy and confirm no overclaiming.
- Confirm no publish/deploy/push/tag/release occurred.
- Confirm no external target scan occurred.

## Phase 4 Seeds

Do not implement these in Phase 3 unless explicitly requested:

- Hosted multi-user dashboard.
- Team/project accounts.
- Cloud trace storage.
- Billing and plan limits.
- Slack/email approval integrations.
- Compliance report exports.
- Production-grade gateway deployment.
