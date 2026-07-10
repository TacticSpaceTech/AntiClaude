# Phase 1 Credible Eval V1 Progress Ledger

Objective: make AntiClaude's eval product consistent, evidence-first, and defensible across CLI, Web, and GitHub Action.

## Prompt-To-Artifact Checklist

| Requirement | Evidence target | Current status |
| --- | --- | --- |
| CLI, Web, and GitHub Action share scan/report semantics or documented compatibility layer with tests | `packages/engine/src/attack-runner.ts`, `app/api/attack/stream/route.ts`, `action/action.yml`, focused tests | Complete. Web route now streams `runScan` progress from `@anticlaude/engine`; action invokes built CLI with quoted argv. Engine tests passed. |
| Reports include payload id/name/category/severity, exact prompt, response excerpt/full response where safe, confidence, detector indicators, judge verdict, remediation, target metadata, errors, reproduction command/config | Engine `ScanReport`/`ScanResult`, CLI reporter, Web result UI/API stream, tests | Complete. `ScanReport` is versioned and includes target metadata plus reproduction info; each `ScanResult` includes request evidence, remediation, status, confidence source, errors, and judge verdict. |
| Web real scan mode never emits simulated findings; demo mode, if present, is explicitly separated | `app/api/attack/stream/route.ts`, `components/security-report.tsx`, page copy/tests | Complete. Web route maps engine results with `isSimulated: false`; error UI states no simulated finding was generated. Route verification returned fail-closed 400 responses for private targets and invalid adapters. |
| Target request behavior explicit/configurable for generic JSON, OpenAI-compatible chat, Anthropic-compatible messages, auth header, and practical custom body mapping | Engine target adapter types, CLI options, Web form/API inputs, docs/tests | Complete. Added target adapters, CLI options, Web advanced controls, docs, and adapter tests. |
| GitHub Action shell-safe, preserves secrets, deterministic fail threshold, stable score/breach/report outputs | `action/action.yml`, action tests/docs | Complete. Action now builds bash argv arrays, uses env inputs, redacts report auth evidence through engine, uses PR comment `--body-file`, validates numeric threshold, and exposes score/breaches/errors/report-path. |
| Docs/product copy aligned with shipped capability; no runtime guard, enterprise control plane, compliance readiness, autonomous remediation claims as shipped | README, action README, docs pages, app copy | Complete. Public docs and app copy use shipped eval/audit wording; forward-looking plan has an explicit status note. |
| Focused tests for every behavioral change | Engine tests plus action/report tests | Complete. Added `target-adapter.test.ts`, smoke report-contract assertions, and `scripts/test-action-yml.mjs`; `pnpm run test` passed. |
| Final verification suite passes | `pnpm run validate:payloads`, `pnpm run test`, `pnpm run build`, `pnpm run build:cli`, CLI smoke checks, route/browser verification, `git status --short` | Complete. Final command evidence recorded below. |

## Commands Run

- `git status --short --branch`: branch `main...origin/main`, untracked `docs/phase-1-long-horizon-goal.md`.
- `sed -n '1,240p' docs/phase-1-long-horizon-goal.md`: loaded acceptance criteria and operating loop.
- `rg --files`: confirmed Next.js app, `@anticlaude/engine`, CLI, composite action, payload library.
- `sed` reads of README, SPEC, upgrade plan, engine runner/detector/reporter/types, CLI scan command, Web stream route, action, and tests.
- `rg -n "simulat|demo|runtime guard|control plane|compliance|enterprise|ANTICLAUDE_SUMMARY|fail-threshold"` across public/docs/action/package paths.
- `pnpm install`: linked root app to workspace `@anticlaude/engine`.
- `pnpm run test:action`: action YAML safety checks passed.
- `pnpm --filter @anticlaude/engine run test`: 6 test files passed, 67 tests passed.
- `pnpm --filter @anticlaude/engine run build`: TypeScript build passed.
- `pnpm run build:cli`: CLI TypeScript build passed.
- `pnpm run build`: payload generation, engine build, and Next production build passed; `/api/attack/stream` compiled as a dynamic route.
- `pnpm dev`: server ready at `http://localhost:3000`.
- `curl -I http://localhost:3000/`: HTTP 200.
- `curl -X POST /api/attack/stream` with `http://127.0.0.1:4567`: HTTP 400, private/reserved address blocked.
- `curl -X POST /api/attack/stream` with invalid adapter: HTTP 400, adapter allowlist returned.
- `pnpm run validate:payloads`: 64 payloads, 0 errors.
- `pnpm run test`: action safety checks plus 6 engine test files, 67 tests passed.
- `node packages/cli/dist/index.js --help`: command help rendered.
- `node packages/cli/dist/index.js scan --help`: adapter/body/threshold options rendered.
- `node packages/cli/dist/index.js badge --score 85`: shields badge URL rendered.
- `git diff --check`: no whitespace errors.

## Slice Log

- 2026-05-08: Started Phase 1 inspection and checklist.
- 2026-05-08: Added engine target adapters, versioned report evidence, web route engine sharing, CLI options, action hardening, public copy reset, tests, and final verification.
