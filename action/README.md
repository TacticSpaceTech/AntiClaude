# AntiClaude GitHub Action

Red-team your AI agent endpoint in CI/CD.

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
          fail-threshold: 70
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `endpoint` | Yes | — | Target AI agent API endpoint URL |
| `auth` | No | — | Authorization header value |
| `count` | No | `12` | Number of payloads to test |
| `variants` | No | `2` | Max variants per payload |
| `timeout` | No | `15000` | Request timeout in ms |
| `output-format` | No | `markdown` | Report format: json, markdown, html |
| `fail-threshold` | No | `70` | Minimum score to pass (0-100) |
| `llm-judge` | No | — | LLM judge provider: openai or anthropic |
| `llm-key` | No | — | API key for LLM judge |
| `comment-on-pr` | No | `true` | Post scan summary as PR comment |

## Outputs

| Output | Description |
|--------|-------------|
| `score` | Security score (0-100) |
| `breaches` | Number of breaches found |
| `report-path` | Path to the generated report file |
