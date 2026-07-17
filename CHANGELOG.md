# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-07-18

Local-first control plane release (Phase 1–3): deterministic evals, CI compare gates, local guard/runtime review, and audit replay.

### Added

#### Eval Lab

- Deterministic eval suites (`scan --suite`) with seedable payload selection
- Built-in CLI suite name: `smoke` (also `builtin:smoke`)
- Local mock fixtures (`anticlaude fixtures`) for generic, OpenAI, Anthropic, tool-call, and support-agent targets
- Report comparison and regression gates (`anticlaude compare`)
- Versioned scan report schema (`reportVersion`) with committed examples under `docs/examples/`

#### Runtime control (local beta)

- Guard policy SDK and local-only HTTP gateway (`anticlaude guard`)
- Built-in CLI policy name: `default` (also `builtin:default`)
- Runtime tool governance policy v2 (allow / block / review)
- Human review queue CLI (`anticlaude review list|show|approve|deny`)
- Local incident index and JSONL audit traces
- Trace replay (`anticlaude replay`)

#### Web

- `/control-plane` local console for agents, tools, reviews, incidents, reports, and policy hits
- Web scan path uses shared engine semantics (no simulated findings)

#### GitHub Action

- Suite, adapter, and compare-gate inputs with safer argv handling

#### Tests & docs

- Expanded engine vitest suite
- Phase 1–3 goal/progress docs and example artifacts
- `SECURITY.md`, release pack hygiene (`pnpm run release:check`)

### Changed

- Relicensed the repository to **AGPL-3.0-only** (aligned with npm package metadata)
- npm packages include LICENSE, engine `exports` map, and CLI `examples/` for first-run paths
- Publish workflow uses npm provenance (`--provenance`)

### Maintenance

- Removed stale root `package-lock.json` (pnpm is the only package manager)
- Added maintenance scripts (`typecheck`, `ci`, `release:check`), Node engines, `.nvmrc`, and expanded `.gitignore`
- CI builds packages, runs tests, and validates pack contents before merge

### Security

- Fail-closed private/reserved address blocking on the web attack stream API
- Auth and secret redaction in reports and traces

## [1.0.0] - 2026-03-16

### Added

- Initial npm release of `anticlaude` and `@anticlaude/engine`
- 64 YAML payloads covering 7/10 OWASP Agentic Top 10 categories
- CLI: `scan`, `audit`, `mcp-scan`, `badge`
- LLM judge detection and MCP server scanner
- GitHub Action and CI/publish workflows
- Next.js marketing site and interactive scanner UI

[Unreleased]: https://github.com/TacticSpaceTech/AntiClaude/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/TacticSpaceTech/AntiClaude/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/TacticSpaceTech/AntiClaude/releases/tag/v1.0.0
