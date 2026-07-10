# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Relicensed the repository to **AGPL-3.0-only** (aligned with npm package metadata).

### Maintenance

- Removed stale root `package-lock.json` (pnpm is the only package manager).
- Added maintenance scripts (`typecheck`, `ci`), Node engines, `.nvmrc`, and expanded `.gitignore`.
- CI now builds packages and runs the full monorepo verification path.

## [1.1.0] - 2026-05-09

Local-first control plane release (Phase 1–3). Not yet published to npm until this tree is tagged.

### Added

#### Eval Lab

- Deterministic eval suites (`scan --suite`) with seedable payload selection
- Local mock fixtures (`anticlaude fixtures`) for generic, OpenAI, Anthropic, tool-call, and support-agent targets
- Report comparison and regression gates (`anticlaude compare`)
- Versioned scan report schema (`reportVersion`) with committed examples

#### Runtime control (local beta)

- Guard policy SDK and local-only HTTP gateway (`anticlaude guard`)
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

- Expanded engine vitest suite (110 tests)
- Phase 1–3 goal/progress docs and example artifacts under `docs/examples/`

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
