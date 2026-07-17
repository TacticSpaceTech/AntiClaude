# AntiClaude GitHub Action

Red-team your AI agent endpoint in CI/CD. Supports deterministic eval suites and baseline report comparison gates so agent security regressions fail the job.

## Usage

```yaml
name: Security Scan
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: TacticSpaceTech/AntiClaude/action@v1
        with:
          endpoint: ${{ secrets.AGENT_ENDPOINT }}
          auth: 'Bearer ${{ secrets.AGENT_TOKEN }}'
          output-format: json
          baseline-report: docs/examples/reports/baseline-safe.json
          fail-on-new-severity: critical,high
          fail-on-category-regression: true
          fail-threshold: 70
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `endpoint` | Yes | — | Target AI agent API endpoint URL |
| `auth` | No | — | Authorization header value |
| `adapter` | No | `generic-json` | Target request adapter: `generic-json`, `openai-chat`, `anthropic-messages`, or `custom-json` |
| `body-field` | No | `message` | JSON field used by `generic-json` |
| `body-template` | No | — | Custom JSON template for `custom-json`; use `{{prompt}}` or `{{promptJson}}` |
| `target-model` | No | — | Model field for OpenAI-compatible or Anthropic-compatible APIs |
| `max-tokens` | No | `1024` | `max_tokens` for Anthropic-compatible APIs |
| `suite` | No | — | Eval suite JSON file with deterministic payload selection |
| `count` | No | `12` | Number of payloads to test |
| `variants` | No | `2` | Max variants per payload |
| `timeout` | No | `15000` | Request timeout in ms |
| `output-format` | No | `markdown` | Report format: json, markdown, html |
| `fail-threshold` | No | `70` | Minimum score to pass (0-100) |
| `baseline-report` | No | — | Optional baseline AntiClaude JSON report for compare gates; requires `output-format: json` |
| `fail-on-score-drop` | No | — | Fail compare gate if score drops by more than this many points |
| `fail-on-new-severity` | No | — | Fail compare gate on new breaches at comma-separated severities |
| `fail-on-new-error` | No | `false` | Fail compare gate if current report has new errors |
| `fail-on-category-regression` | No | `false` | Fail compare gate if any OWASP category score regresses |
| `llm-judge` | No | — | LLM judge provider: openai or anthropic |
| `llm-key` | No | — | API key for LLM judge |
| `comment-on-pr` | No | `true` | Post scan summary as PR comment |

## Outputs

| Output | Description |
|--------|-------------|
| `score` | Security score (0-100) |
| `breaches` | Number of breaches found |
| `errors` | Number of scan request errors |
| `report-path` | Path to the generated report file |
| `compare-path` | Path to the generated compare report JSON file, when `baseline-report` is set |

Compare gates run locally inside the action and use the same `anticlaude compare` command as the CLI.
