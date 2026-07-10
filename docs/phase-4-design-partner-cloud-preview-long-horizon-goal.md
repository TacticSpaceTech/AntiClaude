# AntiClaude Phase 4 Long-Horizon Goal: Design Partner Cloud Preview

## Phase 4 Name

**Design Partner Cloud Preview: Projects + Cloud Sync + Team Review + Runtime Gateway Hardening**

## Primary Objective

Turn the Phase 3 local Runtime Control Beta into a private design-partner preview that can support real teams reviewing real agent security evidence, while preserving explicit safety boundaries.

The finished phase should prove this workflow:

1. A developer runs local eval/runtime checks.
2. The CLI can package a redacted report, runtime trace, review queue item, and policy snapshot.
3. The package can be synced to a project/workspace backend in an idempotent, signed, auditable way.
4. A team member can inspect report history, regressions, incidents, and pending reviews in a cloud preview UI.
5. A reviewer can approve or deny a runtime review from the cloud preview UI or an integration stub.
6. The local gateway can poll or receive a decision update and complete the review lifecycle.
7. Audit evidence can be exported as a design-partner evidence pack.
8. Plan limits can be modeled without live billing.
9. Gateway deployment hardening can be tested locally or in a controlled preview environment.
10. The product copy remains honest: private preview, not public SaaS launch or certified compliance product.

## Why This Goal Is Bigger

Phase 1 made findings and reports real.

Phase 2 made evaluation reproducible with local control-plane artifacts.

Phase 3 proved runtime tool governance, local review, and incident replay.

Phase 4 should answer the next hard product question:

> Can AntiClaude become useful for a team, not only for one local developer?

That requires account/project boundaries, cloud artifact sync, shared review queues, history, integrations, and gateway hardening. This is bigger than adding UI polish because it introduces trust, tenancy, storage, lifecycle, and operational safety.

## Product North Star

AntiClaude should help a small design-partner team answer:

1. Which projects and agents are protected?
2. What changed between the last safe baseline and the current run?
3. Which runtime incidents need human review?
4. Who approved or denied a risky action, and why?
5. Can the team export evidence for internal review without claiming certification?
6. Can local runtime control stay useful when decisions involve more than one person?

## Phase 4 Scope

### 1. Project And Workspace Model

- Add a data model for:
  - workspace
  - project
  - environment
  - agent
  - tool
  - policy profile
  - scan report
  - runtime trace
  - incident
  - review request
  - review decision
  - audit event
- Include ownership boundaries and access rules.
- Design for multiple projects in one workspace.
- Keep the first implementation narrow enough for a private preview.

### 2. Cloud Artifact Sync Protocol

- Add a local artifact bundle format for reports, traces, runtime policies, and reviews.
- Include schema version, project id, agent id, createdAt, content hash, redaction metadata, and signature metadata.
- Support idempotent upload by content hash and stable ids.
- Add CLI commands for:
  - `sync status`
  - `sync package`
  - `sync push`
  - `sync pull-decisions`
- Add dry-run mode.
- Add tests that prove sensitive fields remain redacted before upload.

### 3. Private Preview Backend

- Add a backend surface for project artifacts.
- Required endpoints:
  - create/list projects
  - upload artifact bundle
  - list reports
  - list incidents
  - list reviews
  - approve/deny review
  - fetch pending decisions
  - export evidence pack
- Add authentication and authorization boundaries.
- Add rate limits and request size limits.
- Add audit logging for every write.
- Avoid public signup unless explicitly requested.

### 4. Cloud Preview UI

- Upgrade the Web app from local example console to a private preview control plane.
- Add project navigation.
- Add report history and baseline comparison views.
- Add runtime incidents and shared review queue.
- Add policy profile viewer.
- Add agent/tool inventory.
- Add audit event timeline.
- Add evidence pack export UI.
- Make preview/demo state explicit.
- Keep local `/control-plane` example mode working.

### 5. Team Review Lifecycle

- Support review states:
  - pending
  - approved
  - denied
  - expired
  - applied
  - superseded
- Require reviewer identity and reason.
- Prevent duplicate decisions.
- Record decision source:
  - local CLI
  - cloud UI
  - integration stub
- Add decision sync from cloud back to local gateway.
- Add expiration and stale-decision handling.

### 6. Approval Integrations

- Add integration architecture for Slack and email approval workflows.
- Start with stubs or local webhook simulators unless real credentials are explicitly provided.
- Required behavior:
  - send review summary
  - include policy id, agent, tool, risk, evidence
  - approve/deny with reason
  - write audit event
  - handle replayed or expired approvals safely
- No real outbound messages without explicit approval.

### 7. Runtime Gateway Hardening

- Add gateway configuration profiles for local, preview, and production-like test mode.
- Add signed decision polling or webhook validation.
- Add health endpoint.
- Add structured runtime metrics.
- Add bounded trace retention settings.
- Add graceful shutdown and backpressure behavior.
- Add config validation and threat-model docs.
- Add tests for fail-closed behavior when cloud decision sync is unavailable.

### 8. Plan Limits Without Live Billing

- Model plan limits in code and UI:
  - projects
  - members
  - reports per month
  - retained traces
  - review requests
  - integrations
- Enforce preview limits locally or in backend tests.
- Do not connect live billing or charge users without explicit approval.
- If Stripe is later added, it must be gated behind a separate approval and test-mode-only first.

### 9. Evidence Pack Exports

- Add export format for internal security review:
  - report summary
  - regression summary
  - policy profile
  - incidents
  - review decisions
  - audit log
  - redaction summary
- Export JSON and Markdown first.
- Optional PDF can be deferred unless the user requests it.
- Avoid compliance certification claims. Call it an evidence pack, not a SOC 2/GDPR report.

### 10. Migration And Compatibility

- Keep Phase 1/2/3 local flows working.
- Preserve existing report schema compatibility.
- Add migrations or schema-versioned readers for new cloud artifacts.
- Add fixtures that convert existing `docs/examples` into cloud artifact bundles.
- Keep no-network local tests possible.

## Non-Goals Unless Explicitly Approved

- Public SaaS launch.
- Public user signup.
- Live billing or charging.
- Production deployment.
- Real Slack/email sends.
- External target scans.
- SOC 2/GDPR certification claims.
- Marketplace or public template ecosystem.
- Push, tag, release, deploy, or publish.

## Suggested Work Slices

1. Repo audit and Phase 4 architecture decision record.
2. Data model and schema versioning.
3. Artifact bundle format and local packaging CLI.
4. Redaction/signing/idempotency tests.
5. Private preview backend API skeleton.
6. Auth and authorization boundary.
7. Cloud preview project/report/incident/review UI.
8. Shared review lifecycle and decision sync.
9. Integration stub architecture.
10. Gateway hardening and cloud-unavailable fail-closed behavior.
11. Plan-limit model without live billing.
12. Evidence pack export.
13. Migration compatibility and local example conversion.
14. End-to-end private preview smoke tests.
15. Docs truth reset and completion audit.

## Acceptance Criteria

### 1. Architecture And Data Model

- Architecture decision record exists.
- Data model covers workspace/project/agent/tool/policy/report/trace/incident/review/audit event.
- Access boundaries are documented.
- Schema versions are explicit.

### 2. Artifact Sync

- CLI can package local report, trace, policy, review, and incident artifacts.
- Bundles include redaction metadata, content hash, and stable ids.
- Dry-run mode shows exactly what would be uploaded.
- Tests prove secrets are not included in upload-ready bundles.

### 3. Private Preview Backend

- Backend can create/list projects and store artifact bundles.
- Backend can list reports/incidents/reviews by project.
- Backend can approve/deny reviews with reason.
- Backend records audit events for writes.
- Authorization tests prove cross-project data is not accessible.

### 4. Cloud Preview UI

- UI can show projects, agents, tools, report history, regressions, incidents, reviews, policy profiles, and audit events.
- UI clearly labels preview/local/example states.
- Local `/control-plane` example mode still works.

### 5. Review Lifecycle

- Review requests can move through pending, approved, denied, expired, applied, and superseded states.
- Duplicate or stale decisions are rejected.
- Cloud decisions can be pulled by the local gateway or CLI.
- Every decision has reviewer identity, source, timestamp, and reason.

### 6. Gateway Hardening

- Gateway has validated config profiles.
- Gateway fails closed when cloud decision sync is unavailable.
- Signed decision or webhook validation is implemented for preview mode.
- Health and metrics endpoints exist.
- Tests cover shutdown, timeout, and unavailable-dependency behavior.

### 7. Integration Stubs

- Slack/email approval adapter interfaces exist.
- Local webhook or stub integration can approve/deny a review.
- No real outbound message is sent by default.
- Replayed/expired integration decisions are rejected.

### 8. Plan Limits

- Plan-limit model exists.
- Preview limits can be enforced in tests.
- UI explains limits without implying paid billing is live.

### 9. Evidence Pack

- JSON and Markdown evidence pack export exists.
- Export includes reports, incidents, policy snapshots, review decisions, audit events, and redaction summary.
- Copy avoids certification claims.

### 10. Verification

Before completion, run at minimum:

```bash
pnpm run validate:payloads
pnpm run test
pnpm run build
pnpm run build:cli
git diff --check
git status --short
```

Additional Phase 4 verification should include:

```bash
node packages/cli/dist/index.js --help
node packages/cli/dist/index.js sync --help
node packages/cli/dist/index.js review --help
node packages/cli/dist/index.js guard --help
```

And local/private-preview smoke checks for:

- artifact package dry-run
- artifact push to local preview backend
- report history render
- incident render
- cloud review approve/deny
- local pull-decisions
- gateway fail-closed when backend is unavailable
- evidence pack export

## Documentation Requirements

Add or update docs for:

- Phase 4 architecture decision record
- project/workspace model
- artifact sync protocol
- private preview backend
- review lifecycle
- integration stubs
- runtime gateway hardening
- plan-limit model
- evidence pack exports
- security boundaries and non-goals

## Completion Audit Requirements

Before marking complete:

- Build a prompt-to-artifact checklist.
- Map every acceptance criterion to concrete files, tests, commands, and observed outputs.
- Re-read public copy and confirm no public SaaS, live billing, production, or certification overclaiming.
- Confirm no publish/deploy/push/tag/release occurred unless explicitly approved.
- Confirm no external target scan occurred unless explicitly approved.

