# CI Regression Gates

AntiClaude CI can gate on both absolute scan score and baseline comparison.

## GitHub Action

```yaml
- uses: TacticSpaceTech/AntiClaude/action@v1
  with:
    endpoint: ${{ secrets.AGENT_ENDPOINT }}
    auth: ${{ secrets.AGENT_AUTH }}
    output-format: json
    suite: docs/examples/suites/phase2-smoke-suite.json
    baseline-report: docs/examples/reports/baseline-safe.json
    fail-threshold: 70
    fail-on-score-drop: 10
    fail-on-new-severity: critical,high
    fail-on-new-error: true
    fail-on-category-regression: true
```

`baseline-report` requires `output-format: json` because the current report must be machine-readable.

## CLI Equivalent

```bash
node packages/cli/dist/index.js scan \
  --endpoint "$AGENT_ENDPOINT" \
  --output json \
  --out current.json \
  --json-summary

node packages/cli/dist/index.js compare \
  baseline.json \
  current.json \
  --fail-on-score-drop 10 \
  --fail-on-new-severity critical,high \
  --fail-on-new-error \
  --fail-on-category-regression
```

## Stable Outputs

The action preserves these outputs:

- `score`
- `breaches`
- `errors`
- `report-path`

It adds:

- `compare-path` when compare gates run

PR comments are written through a temporary Markdown file and `gh pr comment --body-file`, avoiding shell interpolation of report body text.
