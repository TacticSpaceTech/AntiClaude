# Phase 3 Runtime Control Beta Progress Ledger

Objective: follow `docs/phase-3-runtime-control-beta-long-horizon-goal.md` by turning the Phase 2 local control-plane alpha into a design-partner-ready runtime control beta for tool-using agents.

## Prompt-To-Artifact Checklist

| Requirement | Concrete artifacts/evidence | Status |
| --- | --- | --- |
| Create/read Phase 3 goal and inspect actual repo/worktree before implementation | `docs/phase-3-runtime-control-beta-long-horizon-goal.md`, `git status --short --branch`, relevant engine/CLI/Web reads | Complete. Goal file created because it was missing; repo state inspected before edits. |
| Reference support-agent fixture with CRM/order lookup, refund/write, data export, external send, and prompt-injection behavior | `packages/engine/src/fixtures.ts`, `packages/cli/src/commands/fixtures.ts`, `packages/engine/src/__tests__/support-agent-fixture.test.ts` | Complete. Engine tests verify read/refund/export/send/injection fixture behavior. |
| Tool governance policy v2 with agent profile, tool inventory, action types, risk levels, env profiles, constraints, sensitive destinations, validation | `packages/engine/src/runtime-policy.ts`, `docs/examples/runtime/support-agent-profile.json`, `runtime-policy.test.ts` | Complete. Runtime profile validation and committed example loading are tested. |
| Runtime decision engine returns allow/block/review with agent/tool/risk/rule/evidence/recommended action | `evaluateRuntimeToolRequest`, `runtime-policy.test.ts` | Complete. Tests cover safe read allow, unsafe write block, export review, external send block, unknown tool fail-closed. |
| Human review queue local storage plus CLI list/show/approve/deny with reasons | `packages/engine/src/review-queue.ts`, `packages/cli/src/commands/review.ts`, `review-queue.test.ts` | Complete. Engine tests cover create/list/get/approve/deny and duplicate decision rejection; CLI builds. |
| Gateway v2 writes review requests, returns 202 with review id, preserves 403 block and allowed forwarding | `packages/engine/src/guard-gateway.ts`, `packages/cli/src/commands/guard.ts`, `guard-gateway.test.ts` | Complete. Tests cover support-agent export 202 + persisted review id, refund 403, safe read 200. |
| Local incident store/query by trace/request/agent/policy/action/tool with redaction coverage | `packages/engine/src/incident-store.ts`, `incident-store.test.ts`, `docs/examples/traces/runtime-incident.jsonl` | Complete. Tests query all required dimensions and assert redacted secret is absent. |
| Web runtime console sections for agents, tools, policy summary, review queue, incident replay, policy hits | `app/control-plane/page.tsx`, `docs/examples/runtime/review-queue.json`, `docs/examples/traces/runtime-incident.jsonl` | Complete. `pnpm run build` prerendered `/control-plane`. |
| CI/runtime regression coverage for safe allow, unsafe block, export/send review, unknown tool fail-closed; existing Action behavior stable | `pnpm run test`, `runtime-policy.test.ts`, `guard-gateway.test.ts`, `scripts/test-action-yml.mjs` | Complete. Full test suite passed, including Action YAML safety checks and 110 engine tests. |
| Docs truth reset for runtime control beta without hosted/team/billing/compliance/production overclaims | README, CLI/engine READMEs, app docs/roadmap, new runtime docs, copy scan | Complete. Overclaim scan hits are explicit negatives, roadmap/planned notes, older goal docs, or domain terms like billing tool names. |
| Required final verification passes and completion audit maps every criterion to evidence | Required commands, local runtime smoke, Web/API checks, completion audit below | Complete. All required command checks passed; Browser plugin execution tool was unavailable, so Web verification used local HTTP + rendered HTML checks. |

## Startup Evidence

- `get_goal`: active goal is `follow the instructions in docs/phase-3-runtime-control-beta-long-horizon-goal.md`.
- `git status --short --branch`: branch `main...origin/main`; Phase 1 and Phase 2 changes remain in the dirty tree and must be preserved.
- `test -f docs/phase-3-runtime-control-beta-long-horizon-goal.md ...`: returned `MISSING`, so the goal file was created in this slice.
- `sed -n '1,320p' docs/phase-3-runtime-control-beta-long-horizon-goal.md`: Phase 3 acceptance criteria loaded after creation.
- `find packages/engine/src packages/cli/src app/control-plane docs/examples -maxdepth 3 -type f | sort`: confirmed current Phase 2 implementation surface.
- `sed` reads of `fixtures.ts`, `guard.ts`, `guard-gateway.ts`, CLI `index.ts`, `guard.ts`, and `fixtures.ts`: confirmed Phase 2 supports generic/tool fixtures, Guard SDK, gateway, `guard`, and `fixtures`, but lacks support-agent, review queue, runtime profile v2, and `review` command.

## Slice Log

- 2026-05-09: Created Phase 3 goal file and progress ledger after confirming the requested goal file was missing.
- 2026-05-09: Added support-agent fixture, runtime policy v2, review queue, gateway runtime review integration, CLI `review`, local incident store, runtime examples, `/control-plane` runtime console, and docs truth reset.
- 2026-05-09: Verification so far: `pnpm --filter @anticlaude/engine run test` passed with 17 files / 110 tests; `pnpm run build:engine`, `pnpm run build:cli`, and `pnpm run build` passed after rebuilding engine before CLI.
- 2026-05-09: Final verification passed: payload validation, full tests, Next build, CLI build, diff whitespace check, CLI help/replay smoke, local runtime 200/403/202 review smoke, review approval smoke, `/control-plane` HTTP/HTML check, and `/api/attack/stream` private-address fail-closed check.

## Final Verification Evidence

| Check | Observed result |
| --- | --- |
| `pnpm run validate:payloads` | Validated 64 payloads, 0 errors. |
| `pnpm run test` | Action YAML safety checks passed; engine test suite passed with 17 files / 110 tests. |
| `pnpm run build` | Payload build, engine build, and Next build passed; `/control-plane` prerendered in the route table. |
| `pnpm run build:cli` | CLI TypeScript build passed. |
| `git diff --check` | Passed with no whitespace errors. |
| `node packages/cli/dist/index.js --help` | Listed `review` command. |
| `node packages/cli/dist/index.js guard --help` | Listed `--runtime-profile`, `--agent-id`, and `--review-store`. |
| `node packages/cli/dist/index.js review --help` | Listed `list`, `show`, `approve`, and `deny`. |
| `node packages/cli/dist/index.js replay docs/examples/traces/sample-trace.jsonl` | Printed 3-event trace replay with prompt block and redaction. |
| Local support-agent + guard smoke | Lookup returned HTTP 200 allowed; refund returned HTTP 403 blocked; export returned HTTP 202 review with `review_9ebdf3c6-756a-4df0-8f98-ed79d2b09ff7`. |
| `anticlaude review` smoke | `review list` showed one pending export review, `review show` printed evidence, `review approve` persisted approval, pending became 0 and approved became 1. |
| Runtime trace replay smoke | `/tmp/anticlaude-runtime-phase3.jsonl` replay printed 20 events covering export review, refund block, and lookup allow. |
| `/control-plane` HTTP/HTML check | HTTP 200; HTML contained `Agents + Tools + Reviews + Incidents`, `Agent Inventory`, `Tool Inventory`, `Review Queue`, `Runtime Incident`, `Policy Hit Details`, `review_example_export_1`, and `runtime.tool.export_customer_data.destination.review`. |
| `/api/attack/stream` fail-closed check | Posting endpoint `http://127.0.0.1:4100/chat` returned HTTP 400 with `Requests to private or reserved addresses are not allowed`. |
| Browser verification attempt | Browser skill loaded; `tool_search "mcp__node_repl__js"` returned 0 tools, so screenshot-level browser verification was not available in this session. |
| Service cleanup | PIDs on ports 4100 and 4101 were killed; `lsof -tiTCP:4100/4101` returned empty. |

## Completion Audit

1. Reference support-agent fixture: satisfied by `fixtures.ts`, CLI `fixtures --kind support-agent`, and `support-agent-fixture.test.ts`.
2. Tool governance policy v2: satisfied by `runtime-policy.ts`, `support-agent-profile.json`, and validation tests.
3. Runtime decision engine: satisfied by `evaluateRuntimeToolRequest` and tests for allow/block/review/fail-closed.
4. Human review queue: satisfied by `review-queue.ts`, `anticlaude review`, tests, and local approve smoke.
5. Gateway v2 review integration: satisfied by `guard-gateway.ts`, CLI guard options, gateway tests, and local 200/403/202 smoke.
6. Local incident store: satisfied by `incident-store.ts`, committed `runtime-incident.jsonl`, and incident query/redaction tests.
7. Web runtime console: satisfied by `/control-plane` runtime sections, Next build, and local HTML content check.
8. CI regression coverage: satisfied by full `pnpm run test`, focused runtime tests, and Action YAML check.
9. Documentation: satisfied by README, app docs/roadmap updates, CLI/engine README updates, and Phase 3 docs.
10. Security/product boundaries: no deploy, publish, push, tag, release, or external target scan was performed; overclaim scan results were reviewed.
