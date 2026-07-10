# AntiClaude Phase 2 Long-Horizon Goal: Control Plane Alpha

## Why This Goal Is Bigger

Phase 1 made AntiClaude credible as an eval/audit scanner across CLI, Web, and CI. The next goal should not be a short cleanup pass. It should move the repo toward the real product thesis:

AntiClaude should become the default npm-native security control plane for tool-using AI agents.

The next long-running phase should therefore build a complete local-first alpha, not just a better scanner:

1. A reproducible eval lab that can compare agent behavior across versions.
2. A runtime guard foundation that can evaluate prompt, tool-call, and output risk.
3. An audit/replay layer that explains what happened after a risky interaction.
4. A CI regression workflow that can block unsafe changes with evidence.
5. A Web experience that can inspect reports, comparisons, traces, and policy decisions without pretending a hosted SaaS exists.

This is intentionally larger than a 20-minute goal. Treat it as a multi-slice product/engineering program.

## Product North Star

AntiClaude should help a JS/TS team answer four questions before and during agent release:

1. Can this agent be broken by repeatable adversarial tests?
2. Did this version regress compared with the previous version?
3. Would a risky prompt, tool call, or output be allowed, blocked, or sent to review?
4. If something went wrong, can we replay the evidence and explain the decision?

## Phase 2 Name

**Control Plane Alpha: Eval Lab + Guard SDK + Audit Replay**

## Primary Objective

Turn AntiClaude from a credible scanner into a local-first agent security control plane alpha:

- Eval Lab: deterministic suites, fixtures, baseline comparisons, stable report schema.
- Guard SDK: policy decisions for prompt, tool-call, and output risk.
- Audit Replay: trace schema, local trace store, CLI/Web replay.
- CI Evidence: score and regression gates with stable machine-readable outputs.
- Honest Product Surface: public copy and docs only claim what the repo actually implements.

## Completion Bar

This phase is complete only when a developer can run everything locally and prove the full workflow:

1. Start mock vulnerable/safe/provider-compatible agents.
2. Run eval suites against them.
3. Compare current report against a baseline.
4. Run a runtime policy decision against prompt/tool/output examples.
5. Capture a trace.
6. Replay the trace in CLI and inspect it in Web.
7. Run GitHub Action-equivalent local checks.
8. Produce docs that explain all of the above without overclaiming hosted, enterprise, compliance, or production gateway features.

## Acceptance Criteria

### 1. Deterministic Eval Lab

- Add local mock agents:
  - vulnerable generic JSON agent
  - safe generic JSON agent
  - OpenAI-compatible chat mock
  - Anthropic-compatible messages mock
  - tool-calling mock with safe and unsafe tool-call paths
- Add deterministic eval suite support:
  - seedable payload selection
  - suite config file format
  - category/severity/tag selection
  - fixed expected outcomes for mock agents
- Add CLI flow:
  - `anticlaude fixtures` or documented fixture command
  - `anticlaude scan --suite <file>`
  - stable JSON report output
- Add tests proving expected pass/fail behavior without real external targets.

### 2. Baseline Comparison and Regression Gates

- Add `anticlaude compare <baseline.json> <current.json>`.
- Compare output must include:
  - score delta
  - new breaches
  - fixed breaches
  - persistent breaches
  - new errors
  - resolved errors
  - changed confidence
  - changed category coverage
- Add machine-readable JSON output for compare.
- Add threshold/gating options:
  - fail on score drop
  - fail on new high/critical breach
  - fail on new error
  - fail on category regression
- Add tests with fixture reports.

### 3. Stable Report Schema and Compatibility

- Document the report contract:
  - `reportVersion`
  - target metadata
  - request evidence
  - response excerpt/full response policy
  - detector indicators
  - judge verdict
  - remediation
  - reproduction command/config
  - error states
- Add JSON schema or equivalent TypeScript schema validation.
- Add committed example reports:
  - safe scan report
  - vulnerable scan report
  - report with errors
  - report with LLM judge unavailable
- Add compatibility tests for report version 1.
- Do not break the existing CI summary line unless a new versioned line is introduced and documented.

### 4. Runtime Guard SDK Foundation

- Create a guard module/package boundary inside the repo, using existing TypeScript patterns.
- Implement a small policy evaluator with decisions:
  - `allow`
  - `block`
  - `review`
- Support three decision surfaces:
  - prompt/input risk
  - tool-call risk
  - output/data-egress risk
- Include policy metadata:
  - rule id
  - severity
  - reason
  - matched evidence
  - recommended action
- Add policy config format:
  - JSON or YAML
  - allow/deny/review rules
  - tool name matching
  - argument constraints
  - sensitive output patterns
- Add tests for:
  - prompt injection intent
  - private data exfiltration attempt
  - unsafe write tool call
  - safe read-only tool call
  - ambiguous action requiring review
- Do not build a hosted gateway yet.

### 5. Local Runtime Gateway Prototype

- Add a local-only prototype, not a deployed service.
- It may be a CLI/dev server command, for example:
  - `anticlaude guard --config anticlaude.policy.yaml --target http://localhost:4000/chat`
  - or `pnpm run guard:dev`
- Prototype must:
  - accept an incoming request
  - evaluate prompt risk before forwarding
  - evaluate model/tool-call-like output where practical
  - emit a policy decision trace
  - return explicit blocked/review responses
- Include tests against local mock targets.
- Clearly label this prototype as local alpha in docs and UI.

### 6. Audit Trace and Replay

- Define a trace schema for:
  - input prompt
  - target adapter/config metadata
  - request id
  - policy decisions
  - scan payload id if applicable
  - tool-call evidence if applicable
  - response evidence
  - redaction metadata
  - timestamps/durations
- Add a local trace writer:
  - JSONL or structured JSON files
  - no secrets stored
  - deterministic test fixtures
- Add CLI replay:
  - `anticlaude replay <trace-file>`
  - summarize timeline
  - show policy decisions
  - show evidence excerpts
- Add Web report/replay view:
  - import or load local/example trace data
  - timeline of prompt -> decision -> response
  - breach/block/error/review states
- Add tests for trace redaction and replay parsing.

### 7. Web Control Plane Alpha

- Keep it local-first and honest.
- Add or improve Web views for:
  - scan report details
  - baseline comparison
  - policy decision inspection
  - trace replay
  - adapter/config summary
  - clear error states
- Web must not:
  - generate simulated vulnerability findings in real scan mode
  - imply hosted dashboards are available
  - imply enterprise compliance readiness
  - hide important target request assumptions
- Add route/manual verification notes or tests for changed Web behavior.

### 8. GitHub Action and CI Maturity

- Preserve existing score/breaches/errors/report-path outputs.
- Add compare/regression support if feasible:
  - optional baseline report path
  - score drop threshold
  - new breach threshold
- Ensure all shell construction remains injection-safe.
- Ensure secrets are redacted in logs, reports, comments, and traces.
- Add focused tests for:
  - threshold behavior
  - compare gate behavior
  - PR comment body safety
  - missing summary behavior

### 9. Documentation and Product Truth Reset

- Add docs for:
  - Eval Lab workflow
  - target adapters
  - suite config
  - baseline comparison
  - report schema
  - runtime policy model
  - local guard prototype
  - audit trace/replay
  - CI examples
- Update public copy so shipped features are clearly:
  - eval scanner
  - skill/MCP audit
  - CI integration
  - local guard prototype if implemented
  - audit/replay alpha if implemented
- Do not claim:
  - hosted enterprise control plane
  - production runtime firewall
  - SOC 2/GDPR compliance readiness
  - autonomous remediation
  - team dashboard
  - billing
  - marketplace

### 10. Security and Abuse Boundaries

- Preserve public Web route protections:
  - block private/reserved hosts
  - block raw IPs where DNS protection is not available
  - validate adapters
  - limit body size
  - keep auth redacted
- Add or preserve redaction tests for:
  - Authorization headers
  - API keys
  - tokens
  - custom headers if supported
- Do not scan external targets unless explicitly authorized by the user.
- Do not publish packages, push tags, deploy, or create releases without explicit approval.

## Suggested Workstream Order

### Slice 1: Repo Audit and Phase 2 Checklist

- Re-check current dirty tree and Phase 1 state.
- Read the changed Phase 1 files rather than assuming memory is current.
- Build a Phase 2 checklist/ledger before editing.
- Confirm existing tests still pass before larger refactors.

### Slice 2: Eval Fixtures and Suites

- Build deterministic local fixtures first.
- Add suite config.
- Add tests proving stable mock behavior.
- This becomes the foundation for all later verification.

### Slice 3: Compare Command

- Add report comparison engine logic.
- Add CLI command.
- Add fixture reports and tests.
- Keep JSON output stable.

### Slice 4: Report Schema Hardening

- Document and validate report schema.
- Add compatibility tests.
- Add example reports.
- Ensure Web/CLI/Action still consume report v1 correctly.

### Slice 5: Runtime Policy Model

- Write `docs/runtime-policy-model.md`.
- Implement policy evaluator only after the model is clear.
- Keep scope small but real: prompt/tool/output decisions.

### Slice 6: Local Guard Prototype

- Build a local-only guard command or dev server.
- Use the policy evaluator.
- Test with local mock targets.
- Emit traces.

### Slice 7: Audit Trace and Replay

- Define trace schema.
- Write local traces.
- Add CLI replay.
- Add Web trace view.
- Add redaction and replay tests.

### Slice 8: Web Control Plane Alpha

- Add report import/inspection, compare view, trace replay, policy decision UI.
- Keep UI evidence-first.
- Avoid SaaS/dashboard overclaiming.

### Slice 9: CI and Action Integration

- Add compare/regression gates to action if feasible.
- Preserve shell safety.
- Expand local action tests.

### Slice 10: Full Verification and Completion Audit

- Run all required checks.
- Manually verify local Web/API routes changed in this phase.
- Re-read every acceptance criterion.
- Confirm no public docs overclaim.
- Confirm no external scans, publishing, deployment, tags, or pushes occurred.

## Required Verification

Before marking the phase complete, run:

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
node packages/cli/dist/index.js scan --help
node packages/cli/dist/index.js badge --score 85
node packages/cli/dist/index.js compare --help
```

Run local workflow checks:

```bash
# Exact commands may change after implementation.
pnpm run fixtures:mock
node packages/cli/dist/index.js scan --endpoint http://127.0.0.1:<mock-port> --count 3 --output json --out /tmp/anticlaude-current.json
node packages/cli/dist/index.js compare docs/examples/reports/baseline-vulnerable.json /tmp/anticlaude-current.json --output json
node packages/cli/dist/index.js replay docs/examples/traces/sample-trace.jsonl
```

Run Web/manual checks after Web changes:

- Start local dev server.
- Confirm home page renders.
- Confirm private/reserved target requests fail closed.
- Confirm invalid adapter requests fail closed.
- Confirm report/compare/replay views render example data.
- Confirm real scan mode does not emit simulated findings.

## Stop Conditions

Stop early only for these blockers:

- Required external credential is missing.
- A target endpoint would be external or unauthorized.
- Acceptance criteria conflict with explicit user instructions.
- Completing a step would require publishing, deploying, pushing, tagging, or releasing.
- A necessary command cannot run in the environment after reasonable local diagnosis.

## Explicit Non-Goals

- Hosted SaaS dashboard.
- Team account system.
- Billing.
- Public payload marketplace.
- Production runtime gateway deployment.
- Compliance certification claims.
- Autonomous remediation.
- npm publishing.
- GitHub release creation.
- Scanning real third-party targets without explicit authorization.

## Copy-Paste Goal Prompt

Use this as the long-running goal prompt:

```text
/goal In /Users/yi/Documents/code/AntiClaude, complete Phase 2 "Control Plane Alpha: Eval Lab + Guard SDK + Audit Replay" as a long-running product and engineering goal.

Primary objective:
Turn AntiClaude from a credible eval/audit scanner into a local-first agent security control plane alpha. The finished phase must include a deterministic eval lab, baseline comparison, stable report schema, runtime guard policy SDK, local guard prototype, audit trace/replay, Web inspection views, CI regression gates, and honest documentation.

Baseline context:
- Phase 1 established credible eval behavior across CLI, Web, and GitHub Action.
- The repo is a Next.js app plus @anticlaude/engine, anticlaude CLI, payload YAML library, and composite GitHub Action.
- Do not assume previous implementation details are current; inspect the actual worktree first.
- Do not publish, deploy, push, tag, release, or scan external targets without explicit approval.

Acceptance criteria:
1. Deterministic eval fixtures exist for vulnerable/safe generic JSON agents, OpenAI-compatible chat, Anthropic-compatible messages, and tool-call-like behavior. Tests prove expected pass/fail behavior without external targets.
2. Eval suite support exists with seedable payload selection, category/severity/tag selection, suite config, and stable JSON reports.
3. Baseline comparison exists through a CLI command such as `anticlaude compare <baseline.json> <current.json>`, with score delta, new/fixed/persistent breaches, errors, confidence changes, category coverage changes, JSON output, and regression gates.
4. Report schema is documented and validated. Example reports are committed. Backward compatibility tests protect reportVersion 1 and the CI summary line.
5. Runtime Guard SDK foundation exists with policy decisions `allow`, `block`, and `review` for prompt risk, tool-call risk, and output/data-egress risk. Policy decisions include rule id, severity, reason, matched evidence, and recommended action.
6. A local-only runtime guard prototype exists and is clearly labeled alpha. It evaluates incoming requests before forwarding, emits policy traces, and returns explicit blocked/review responses where applicable.
7. Audit trace and replay exist with a redacted trace schema, local trace writer, CLI replay command, and Web trace inspection view.
8. Web becomes a local-first control plane alpha for inspecting scan reports, baseline comparisons, policy decisions, and trace replay. It must not imply hosted dashboards or generate simulated findings in real scan mode.
9. GitHub Action and CI behavior support stable score/breaches/errors/report outputs and, if feasible, compare/regression gates. Shell safety and secret redaction must remain tested.
10. Public docs and copy stay honest: shipped eval/audit/CI/local-alpha features only. No hosted enterprise control plane, production firewall, SOC 2/GDPR readiness, autonomous remediation, billing, marketplace, or team dashboard claims.
11. Security boundaries are preserved: Web route target validation, body size limits, adapter validation, auth redaction, no unauthorized external scans.
12. Focused tests exist for each behavioral change, and final verification passes.

Operating loop:
1. Start read-only: run git status, inspect Phase 1 changes, read the relevant engine/CLI/Web/Action/docs/tests files, and build a Phase 2 progress ledger.
2. Work in vertical slices:
   - fixtures and suite config
   - compare command
   - report schema hardening
   - runtime policy model and SDK
   - local guard prototype
   - audit trace/replay
   - Web control plane alpha views
   - Action/CI regression gates
   - docs and product truth reset
3. Add tests before or alongside risky behavior changes.
4. Run the narrowest relevant test after each slice.
5. Keep a progress ledger with files changed, commands run, and observed outputs.
6. Before completion, perform a prompt-to-artifact audit against every acceptance criterion.

Final verification:
- pnpm run validate:payloads
- pnpm run test
- pnpm run build
- pnpm run build:cli
- node packages/cli/dist/index.js --help
- node packages/cli/dist/index.js scan --help
- node packages/cli/dist/index.js badge --score 85
- node packages/cli/dist/index.js compare --help
- local mock-agent scan checks
- local compare checks
- local replay checks
- Web/API route verification for changed views and endpoints
- git diff --check
- git status --short

Stop conditions:
Stop early only if a required external credential is missing, a target would be unauthorized, requirements conflict, the environment blocks necessary commands after diagnosis, or continuing would require publishing/deploying/pushing/tagging/releasing.

Final response:
Summarize changes by area: fixtures, eval suites, engine, CLI, Web, Action, docs, tests, guard SDK, local gateway, trace/replay. List final verification commands and results, residual risks, deferred Phase 3 work, and final git status.
```

## Phase 3 Seeds After This Goal

Do not implement these in Phase 2 unless explicitly requested:

- Hosted multi-user dashboard.
- Team/project accounts.
- Cloud trace storage.
- Policy approval workflow with humans in the loop.
- Billing and plan limits.
- Public payload marketplace.
- Production-grade gateway deployment.
- Third-party integrations such as Slack/email approval.
- Compliance report exports.
