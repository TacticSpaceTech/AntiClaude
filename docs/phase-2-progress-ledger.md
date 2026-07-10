# Phase 2 Control Plane Alpha Progress Ledger

Objective: complete `docs/phase-2-control-plane-alpha-long-horizon-goal.md` by turning AntiClaude into a local-first control plane alpha with Eval Lab, Guard SDK, Audit Replay, Web inspection, CI evidence, and honest documentation.

## Prompt-To-Artifact Checklist

| Requirement | Concrete artifacts/evidence | Status |
| --- | --- | --- |
| Start read-only: check worktree, inspect actual Phase 1 state, read relevant engine/CLI/Web/Action/docs/tests, build ledger, confirm tests pass | `git status --short --branch`, `docs/phase-2-control-plane-alpha-long-horizon-goal.md`, package/CLI/engine reads, `pnpm run test` | Complete. Baseline test passed before Phase 2 edits. |
| Deterministic eval fixtures for vulnerable/safe generic JSON agents, OpenAI-compatible chat, Anthropic-compatible messages, and tool-call-like behavior | Fixture server/module, fixture CLI/docs, tests that scan local fixtures only | Complete. Added `packages/engine/src/fixtures.ts`, `anticlaude fixtures`, and fixture scan tests for all required mock kinds. |
| Eval suite support with seedable payload selection, category/severity/tag selection, suite config, stable JSON reports | Engine suite types/loader/selection, `scan --suite`, example suite docs/tests | Complete. Added `EvalSuiteConfig`, `eval-suite.ts`, `scan --suite`, and `docs/examples/suites/phase2-smoke-suite.json`. |
| Baseline comparison through `anticlaude compare <baseline.json> <current.json>` with score delta, breach/error/confidence/category diffs, JSON output, regression gates | Engine compare module, CLI command, fixture reports, compare tests | Complete. Added `compare.ts`, `anticlaude compare`, example report fixtures, regression gates, and tests. |
| Report schema documented and validated, examples committed, reportVersion 1 compatibility protected, CI summary stable | `docs/report-schema.md`, schema/validator/tests, example reports | Complete. Added v1 validator, docs, committed examples, and compare loader validation. |
| Runtime Guard SDK with `allow`/`block`/`review` for prompt, tool-call, and output risk; policy config and tests | Guard types/evaluator/config loader/tests, `docs/runtime-policy-model.md` | Complete. Added policy evaluator, YAML loader, policy docs, and prompt/tool/output tests. |
| Local-only runtime guard prototype | CLI command or dev server, tests against mock target, trace emission, alpha docs | Complete. Added `anticlaude guard`, local HTTP gateway, mock-target tests, trace emission, and alpha docs. |
| Audit trace schema, local trace writer, CLI replay, Web trace view, redaction/replay tests | Trace types/writer/parser, `anticlaude replay`, example traces, Web page/API | Complete. Added trace schema/writer/parser, CLI replay, example trace, redaction tests, and `/control-plane` trace view. |
| Web local-first control plane alpha for report, compare, policy decisions, trace replay; no hosted/SaaS overclaims or simulated findings | Web routes/components, manual route verification, copy scan | Complete. Added `/control-plane`, navigation, local example report/compare/policy/trace views, and route verification note. |
| GitHub Action/CI support stable outputs and feasible compare/regression gates; shell safety and redaction tested | `action/action.yml`, action tests, docs | Complete. Added suite/compare gate inputs, `compare-path`, safe argv compare step, PR compare report section, and action safety tests. |
| Security boundaries preserved: target validation, body limits, adapter validation, auth redaction, no unauthorized external scans | Route code/tests/manual verification, redaction tests | Complete. Web API fail-closed checks returned 400/413, route maps real results with `isSimulated: false`, and trace/report redaction tests passed. |
| Final verification passes: payload validation, tests, build, CLI build, CLI smokes, local workflow checks, Web/API verification, diff check, status | Final command outputs | Complete. All required final commands passed; final status remains a review-ready dirty tree with Phase 1 and Phase 2 changes. |

## Startup Evidence

- `git status --short --branch`: branch `main...origin/main`; Phase 1 changes are still in the dirty tree and must be preserved.
- `sed -n '1,560p' docs/phase-2-control-plane-alpha-long-horizon-goal.md`: acceptance criteria loaded.
- `find packages/engine/src packages/cli/src app/api action scripts docs -maxdepth 3 -type f | sort`: confirmed current implementation surface.
- `cat package.json packages/engine/package.json packages/cli/package.json`: current scripts and package boundaries inspected.
- `sed` reads of `packages/cli/src/index.ts`, `packages/cli/src/commands/scan.ts`, `packages/engine/src/types.ts`, and `packages/engine/src/index.ts`: confirmed current CLI commands and Phase 1 engine report/adapters.
- `pnpm run test`: passed. Action YAML safety checks passed; engine suite passed 6 files / 67 tests.
- `pnpm --filter @anticlaude/engine run test`: after Slice 2, passed 8 files / 74 tests.
- `pnpm run build:cli`: passed after adding `scan --suite` and `fixtures`.
- `node packages/cli/dist/index.js fixtures --help`: rendered fixture kinds.
- `node packages/cli/dist/index.js scan --help | rg -- "--suite|--adapter|--count"`: confirmed suite option is exposed.
- `pnpm --filter @anticlaude/engine run test`: after Slice 3, passed 9 files / 77 tests.
- `pnpm run build:engine && pnpm run build:cli`: passed after compare exports and CLI command.
- `node packages/cli/dist/index.js compare --help`: rendered compare command and gate options.
- `node packages/cli/dist/index.js compare docs/examples/reports/baseline-safe.json docs/examples/reports/current-vulnerable.json --output json --fail-on-new-severity critical`: expected `status=1`, `scoreDelta=-19`, `newBreaches=1`, `failed=true`.
- `pnpm --filter @anticlaude/engine run test`: after Slice 4, passed 10 files / 84 tests.
- `pnpm run build:engine && pnpm run build:cli`: passed after report schema validator and export updates.
- `pnpm --filter @anticlaude/engine run test`: after Guard/trace/gateway slice, passed 13 files / 95 tests.
- `pnpm run build:engine && pnpm run build:cli`: passed after `guard` and `replay` CLI commands.
- `node packages/cli/dist/index.js guard --help`: rendered local-only Guard alpha gateway options.
- `node packages/cli/dist/index.js replay docs/examples/traces/sample-trace.jsonl`: replayed 3 trace events with a BLOCK decision.
- `node packages/cli/dist/index.js replay docs/examples/traces/sample-trace.jsonl --output json`: parsed `eventCount=3`, `requestIds=["req_sample"]`.
- `pnpm run build`: passed after Web route addition; Next route output included static `/control-plane`.
- `curl -sS -D /tmp/anticlaude-control-plane.headers http://localhost:3000/control-plane -o /tmp/anticlaude-control-plane.html`: returned HTTP `200 OK`.
- `node` HTML assertion against `/tmp/anticlaude-control-plane.html`: `ok=true`, `missing=[]`, `bytes=182312`.
- `pnpm exec playwright --version`: failed with `Command "playwright" not found`; screenshot-level QA not available in this environment.
- `rg -n "hosted|billing|marketplace|SOC 2|GDPR readiness|production runtime firewall|production firewall|team dashboard|cloud report history|\\$19|\\$49|Compliance Standard|Compliance\\}" ...`: remaining hits are explicit negatives, roadmap notes, or payload/policy test strings.
- `pnpm run test:action`: passed after Action compare gate changes.
- `pnpm run build`: passed after docs/Web/copy changes; route output still included static `/control-plane`.
- `pnpm run validate:payloads`: passed, 64 payloads validated with 0 errors.
- `pnpm run test`: passed, Action safety checks plus engine 13 files / 95 tests.
- `pnpm run build && pnpm run build:cli`: passed; Next route output included static `/control-plane`.
- CLI smoke checks passed: `--help`, `scan --help`, `badge --score 85`, `compare --help`, `guard --help`, and `replay docs/examples/traces/sample-trace.jsonl`.
- Local workflow check passed after switching from blocking `execFileSync` to async `spawn`: mock scan `score=75`, `attempts=2`, `breaches=1`, `errors=0`; compare `scoreDelta=-25`, `newBreaches=1`; guard gateway `HTTP 403`, `status=blocked`, `traceEvents=7`, `redacted=true`.
- Web/API checks passed: `/` HTTP 200 with expected localized content; `/control-plane` HTTP 200 with report/compare/policy/trace content; private target returned HTTP 400; invalid adapter returned HTTP 400; oversized request returned HTTP 413.
- `rg -n "isSimulated: false|No simulated finding" app/api/attack/stream/route.ts components/security-report.tsx`: confirmed real scan route marks streamed results as non-simulated and UI error copy does not synthesize findings.
- `git diff --check`: passed.
- `git status --short --branch`: branch `main...origin/main`; dirty tree contains Phase 1 plus Phase 2 modified/untracked files.

## Slice Log

- 2026-05-09: Created Phase 2 ledger after read-only startup and baseline test.
- 2026-05-09: Completed deterministic fixture and eval suite slice.
- 2026-05-09: Completed baseline comparison and regression gate slice.
- 2026-05-09: Completed report schema v1 validation, documentation, and example report slice.
- 2026-05-09: Completed Guard SDK, local gateway alpha, JSONL trace writer, and CLI replay core slice.
- 2026-05-09: Completed Web control-plane alpha route and route verification. Browser Node REPL and local Playwright were unavailable, so QA is build/HTTP/HTML based.
- 2026-05-09: Completed Action compare gates and docs truth reset for shipped local eval/audit/control-plane alpha scope.
- 2026-05-09: Completed final verification and prompt-to-artifact audit. No publishing, deployment, pushing, tagging, releasing, or authorized-external-target scanning was performed.

## Completion Audit

1. Deterministic fixtures: satisfied by `packages/engine/src/fixtures.ts`, `anticlaude fixtures`, and fixture tests for vulnerable/safe generic, OpenAI-compatible, Anthropic-compatible, and tool-calling mocks.
2. Eval suite support: satisfied by `eval-suite.ts`, `scan --suite`, suite metadata in reports, and `docs/examples/suites/phase2-smoke-suite.json`.
3. Baseline comparison: satisfied by `compare.ts`, `anticlaude compare`, JSON/Markdown output, regression gate options, and compare tests.
4. Report schema: satisfied by `report-schema.ts`, `docs/report-schema.md`, four committed example reports, and compatibility tests.
5. Guard SDK: satisfied by `guard.ts`, policy config loader, default policy, `docs/runtime-policy-model.md`, and prompt/tool/output tests.
6. Local guard prototype: satisfied by `guard-gateway.ts`, `anticlaude guard`, mock-target gateway tests, trace emission, and `docs/local-guard-prototype.md`.
7. Audit trace/replay: satisfied by `trace.ts`, JSONL writer/parser, `anticlaude replay`, example trace, redaction tests, and `/control-plane` trace view.
8. Web control plane alpha: satisfied by `/control-plane`, navigation, static example report/compare/policy/trace rendering, and `docs/phase-2-web-route-verification.md`.
9. Action/CI maturity: satisfied by preserved outputs, added `compare-path`, suite and compare gate inputs, safe argv construction, PR comment body-file handling, and action tests.
10. Honest docs/copy: satisfied by README/docs updates and copy scan; hosted dashboards, billing, production firewall, compliance readiness, marketplace, and team dashboard are either absent or explicitly marked not shipped/planned.
11. Security boundaries: satisfied by Web API fail-closed checks, body limit check, adapter validation, report/trace redaction tests, and no external scan execution.
12. Focused tests/final verification: satisfied by final payload validation, full test, build, CLI smoke, local workflow, Web/API, diff check, and status commands.
