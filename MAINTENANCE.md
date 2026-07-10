# Maintenance Guide

Operational checklist for keeping AntiClaude healthy after long gaps.

## Canonical surfaces

| Surface | Canonical value |
| --- | --- |
| GitHub | https://github.com/TacticSpaceTech/AntiClaude |
| npm CLI | `anticlaude` |
| npm engine | `@anticlaude/engine` |
| License | **AGPL-3.0-only** |
| Package manager | **pnpm** only (`packageManager` field in root `package.json`) |
| Node | `>=18` (CI uses 22; see `.nvmrc`) |

Do not reintroduce root `package-lock.json`. Use `pnpm install` / `pnpm-lock.yaml`.

## Local verification (required before PR / release)

```bash
pnpm install
pnpm run ci
```

`pnpm run ci` runs:

1. Payload schema validation
2. Payload build
3. Engine + CLI typecheck/build
4. Full test suite (Action YAML safety + engine vitest)
5. Next.js production build (when time allows for release; always run before tag)

For a faster loop while editing engine/CLI only:

```bash
pnpm run validate:payloads
pnpm run build:payloads
pnpm run typecheck
pnpm run test
```

## Versioning

- Packages `anticlaude` and `@anticlaude/engine` share the same semver for public releases.
- Bump both `packages/*/package.json` versions together.
- CLI `--version` reads `packages/cli/package.json` at runtime.
- Update `CHANGELOG.md` under `[Unreleased]` as you work; move entries into a version section on release.
- Tag format: `vX.Y.Z` (triggers npm publish workflow).

## Release checklist

1. Working tree clean; `main` green on CI
2. `CHANGELOG.md` has a dated section for the release
3. Versions bumped in `packages/engine` and `packages/cli`
4. `pnpm run ci` passes locally
5. Push commit, then `git tag vX.Y.Z && git push origin vX.Y.Z`
6. Confirm GitHub Actions **Publish to npm** succeeds
7. Smoke: `npx anticlaude@X.Y.Z --help` and a fixtures-based scan

## Security boundaries (do not regress)

- Web `/api/attack/stream` must fail closed on private/reserved targets
- Real scan mode must not emit simulated vulnerability findings
- Auth headers and secrets must be redacted in reports/traces
- Do not scan unauthorized external endpoints in tests or docs demos
- Guard/runtime features are **local-only beta**, not a hosted production firewall

## Product honesty

Shipped today: local eval, compare gates, skill/MCP audit, local guard gateway, runtime review queue, incident/trace replay, control-plane UI for **local examples**.

Not shipped: multi-tenant SaaS, billing, production runtime mesh, SOC 2/GDPR readiness claims.

## Repo identity

If a personal fork is used as `origin`, keep `upstream` pointed at TacticSpaceTech:

```bash
git remote -v
git remote add upstream https://github.com/TacticSpaceTech/AntiClaude.git  # if missing
git fetch upstream
```

Push maintenance work to the org repo when ready so npm badges, CI, and docs stay aligned.

## After a long pause

1. `git status` — recover any dirty Phase work before rewriting history
2. `pnpm install` — refresh lockfile if Node major changed
3. `pnpm run ci` — establish a green baseline
4. Skim `CHANGELOG.md` + `docs/phase-*-progress-ledger.md` for what already shipped locally
5. Prefer small PRs over another multi-month uncommitted spike
