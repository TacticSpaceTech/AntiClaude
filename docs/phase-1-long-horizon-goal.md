# AntiClaude Phase 1 Long-Horizon Goal

## Current Repo Facts

- Repo shape: Next.js web app + `@anticlaude/engine` package + `anticlaude` CLI package + composite GitHub Action.
- Existing commands verified on 2026-05-08:
  - `pnpm run validate:payloads`: 64 payloads, 0 errors.
  - `pnpm run test`: 5 test files passed, 61 tests passed when allowed to bind a local `127.0.0.1` smoke server.
  - `pnpm run build`: payload generation, engine build, and Next.js production build passed when Turbopack was allowed to create its worker process.
  - `pnpm run build:cli`: CLI TypeScript build passed.
  - `git status --short`: clean after verification.
- Current product is already a credible eval/audit scanner foundation:
  - CLI commands: `scan`, `audit`, `mcp-scan`, `badge`.
  - Engine modules: payload loader, attack runner, detector, skill auditor, MCP scanner, reporter, optional LLM judge.
  - Web scan route has real outbound attack execution and basic public abuse controls.
  - GitHub Action exists for CI scanning.
- Main strategic mismatch: `docs/agent-product-upgrade-plan.md` points toward Eval + Runtime Guard + Audit control plane, but the actual shipped code is still Eval/Audit only. The next phase should not jump straight to runtime gateway before the eval product is made reliable, consistent, and defensible.

## Long-Term Product Goal

AntiClaude should become the default npm-native security control plane for tool-using AI agents:

1. Evaluate agents before release with repeatable adversarial tests.
2. Guard risky tool actions at runtime with explicit policy decisions.
3. Audit and replay incidents with enough evidence to explain what happened.

The wedge remains developer-first: `npx anticlaude` should be the fastest trustworthy way for JS/TS teams to test an agent endpoint or tool/MCP definition.

## This Phase Goal

Ship "Credible Eval V1": one trustworthy eval product across CLI, Web, and CI.

This phase is complete only when:

1. CLI, Web, and GitHub Action use consistent engine behavior or a clearly documented shared compatibility layer.
2. Reports are evidence-first: raw prompt/response trace, confidence source, OWASP mapping, remediation, reproducible command/config, and explicit error states.
3. Web real scan mode is clearly separated from any demo behavior and does not generate simulated vulnerability findings.
4. Target request behavior is documented and configurable enough for common agent endpoints without relying on hidden assumptions.
5. CI usage is shell-safe, threshold behavior is tested, and machine-readable JSON remains stable.
6. Public-facing docs stop overclaiming beyond actual capabilities.
7. The verification suite passes:
   - `pnpm run validate:payloads`
   - `pnpm run test`
   - `pnpm run build`
   - `pnpm run build:cli`
   - targeted CLI smoke checks after CLI changes
   - browser/manual route verification after Web UI or API route changes

## Feature Targets

P0:

- Shared scan semantics: eliminate or justify duplicated detection/variant logic between `packages/engine` and `app/api/attack/stream/route.ts`.
- Stable report contract: version the JSON report shape and preserve the CI summary line.
- Endpoint adapters: support generic JSON endpoint, OpenAI-compatible chat, Anthropic-compatible messages, and custom request body mapping where practical.
- Evidence-first report UI/CLI: show request, response, detector indicators, judge verdict if used, remediation, and reproduction steps.
- GitHub Action hardening: avoid shell argument injection, preserve secrets, fail reliably by threshold, and post concise PR evidence.
- Trust reset copy: align landing/docs claims with actual scanner/auditor capability.
- Verification automation: add or document one command sequence that approximates CI locally.

P1:

- Baseline comparison between two reports.
- Local mock-agent fixtures for deterministic demos and tests.
- LLM judge provider docs and failure behavior.
- Better MCP scan parsing for explicit config paths.
- Initial runtime policy model document, without implementing the gateway yet.

Not in this phase:

- Runtime gateway service.
- Team dashboard.
- Billing.
- Public payload marketplace.
- Broad compliance claims.
- Publishing to npm or GitHub releases without explicit user approval.

## Copy-Paste Goal Prompt

Use this as the long-running goal prompt:

```text
/goal In /Users/yi/Documents/code/AntiClaude, complete Phase 1 "Credible Eval V1" without stopping until the product is a trustworthy eval/audit scanner across CLI, Web, and GitHub Action.

Context you must treat as baseline:
- This is a monorepo with a Next.js web app, @anticlaude/engine, anticlaude CLI, payload YAML library, and composite GitHub Action.
- Verified baseline on 2026-05-08:
  - pnpm run validate:payloads passed with 64 payloads and 0 errors.
  - pnpm run test passed with 5 test files and 61 tests when local 127.0.0.1 binding was allowed for the smoke test.
  - pnpm run build passed when Next/Turbopack was allowed to create its worker process.
  - pnpm run build:cli passed.
  - git status --short was clean after verification.
- The strategic direction is Eval -> Runtime Guard -> Audit, but this phase must finish Credible Eval V1 before building a runtime gateway.

Primary objective:
Make AntiClaude's eval product consistent, evidence-first, and defensible across CLI, Web, and CI.

Acceptance criteria:
1. CLI, Web, and GitHub Action either share the same scan/report semantics from @anticlaude/engine or have a documented compatibility layer with tests proving equivalent behavior for core cases.
2. Reports include enough evidence to reproduce and debug findings: payload id/name/category/severity, exact prompt sent, response excerpt/full response where safe, confidence, detector indicators, optional LLM judge verdict, remediation, target metadata, errors, and reproduction command or config.
3. Web real scan mode never emits simulated findings. If a demo mode exists, it is explicitly named and separated in code, UI, and docs.
4. Target request behavior is explicit and configurable enough for common agent endpoints: generic JSON endpoint, OpenAI-compatible chat, Anthropic-compatible messages, and auth header handling. Do not silently hide important request assumptions.
5. GitHub Action is hardened against shell argument injection, preserves secrets in logs/comments, handles fail-threshold deterministically, and exposes stable score/breach/report outputs.
6. Docs and product copy are aligned with actual capability. Do not claim runtime guard, enterprise control plane, compliance readiness, or autonomous remediation as shipped features unless implemented and verified.
7. The repo has focused tests for every behavioral change. Add tests before or alongside risky refactors.
8. Do not publish packages, push tags, deploy, contact real third-party targets, or scan endpoints the user did not authorize.

Operating loop:
1. Inspect before editing:
   - Run git status --short --branch.
   - Read README.md, SPEC.md, docs/agent-product-upgrade-plan.md, packages/engine/src, packages/cli/src, app/api/attack/stream/route.ts, action/action.yml, and existing tests.
   - Build a checklist that maps each acceptance criterion to files and tests.
2. Work in small vertical slices:
   - Pick the highest-risk acceptance criterion not yet satisfied.
   - Make the smallest coherent code/doc/test changes.
   - Prefer existing project patterns and TypeScript types.
   - Do not redesign unrelated UI or architecture.
3. Verify after each slice:
   - Run the narrowest relevant test first.
   - Then run wider checks before moving to the next slice.
   - If a check fails, diagnose from the actual error, fix, and rerun.
4. Keep a progress ledger:
   - Record completed items, files changed, commands run, and observed outputs.
   - Do not mark an item complete without command output, test evidence, code reference, or manual verification evidence.
5. Completion audit before declaring complete:
   - Re-read the acceptance criteria.
   - Re-run final verification:
     - pnpm run validate:payloads
     - pnpm run test
     - pnpm run build
     - pnpm run build:cli
     - targeted CLI smoke checks such as `node packages/cli/dist/index.js --help` and at least one harmless command like `node packages/cli/dist/index.js badge --score 85`
     - browser or route verification for any Web UI/API changes
     - git status --short
   - Confirm only intended files changed.
   - Confirm no new docs overclaim beyond implementation.
   - Confirm no known critical security issue remains in CLI/Web/Action paths touched by this work.

Repair policy:
- If tests fail, fix the implementation unless the test itself is demonstrably wrong; if changing tests, explain why.
- If sandbox blocks a necessary command, rerun with the required permission and record the exact blocker.
- If dependency/network install is required, use the locked install command first: `pnpm install --frozen-lockfile`.
- If a verification command is impossible in the environment, stop only after documenting the blocker, the exact command, the error, and the closest completed substitute.

Stop conditions:
Mark the goal complete only when every acceptance criterion is satisfied and the completion audit passes.
Stop early only for one of these blockers:
- Required external credential or authorized target is missing.
- A necessary command cannot run even after the proper permission path.
- Acceptance criteria conflict with each other or with explicit user instructions.
- Continuing would require publishing, deploying, pushing, tagging, or scanning an unauthorized external target.

Final response requirements:
- Summarize what changed by area: engine, CLI, Web, Action, docs, tests.
- List final verification commands and results.
- List any residual risks or intentionally deferred P1 items.
- Include the final git status.
```

## Recommended First Work Slice

Start with consistency and trust, not new runtime features:

1. Compare `packages/engine/src/attack-runner.ts` with `app/api/attack/stream/route.ts`.
2. Decide whether the Web route can call a shared engine-compatible scanner or should extract shared pure logic for Edge compatibility.
3. Add tests that prove detector/report behavior matches for representative payloads.
4. Harden `action/action.yml` argument construction before expanding features.
5. Only then improve reporting and docs.
