# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.1.x | Yes |
| 1.0.x | Best-effort |
| < 1.0 | No |

## Reporting a vulnerability

If you find a security issue **in AntiClaude itself** (CLI, engine, GitHub Action, or web API), please report it privately when possible:

1. Prefer [GitHub Security Advisories](https://github.com/TacticSpaceTech/AntiClaude/security/advisories/new) on this repository.
2. If that is unavailable, open a GitHub issue **without** exploit detail and ask for a private channel.

Please include:

- Affected package/version (`anticlaude`, `@anticlaude/engine`, Action ref)
- Impact and reproduction steps
- Whether a public PoC already exists

We aim to acknowledge reports within a reasonable time and coordinate disclosure.

## Out of scope

- **False positives/negatives in attack payloads or detectors** used against third-party agents — file a normal issue or PR to improve rules/payloads.
- **Scanning systems you do not own or lack authorization to test** — that is your responsibility; AntiClaude must not be used for unauthorized attacks.
- **Production runtime firewall guarantees** — Guard and runtime control are **local-only beta** prototypes, not a hosted or certified security control.

## Safe use

- Only target agents and endpoints you are authorized to test.
- Prefer local fixtures (`anticlaude fixtures`) for demos and CI.
- Treat scan reports and traces as sensitive; they may contain prompt fragments. Secrets should be redacted by the engine, but do not commit raw production traces.
