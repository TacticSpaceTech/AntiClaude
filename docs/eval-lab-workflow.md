# Eval Lab Workflow

AntiClaude Eval Lab is a local workflow for repeatable agent security checks.

## 1. Start A Mock Agent

```bash
node packages/cli/dist/index.js fixtures --kind vulnerable-generic --port 4100
```

Available fixture kinds:

- `vulnerable-generic`
- `safe-generic`
- `openai-chat`
- `anthropic-messages`
- `tool-calling`

## 2. Run A Deterministic Suite

```bash
node packages/cli/dist/index.js scan \
  --endpoint http://127.0.0.1:4100/chat \
  --adapter generic-json \
  --suite docs/examples/suites/phase2-smoke-suite.json \
  --output json \
  --out current.json
```

Suite config supports:

- `seed`
- `count`
- `categories`
- `severities`
- `tags`
- `payloadIds`
- `maxVariants`

## 3. Compare Against Baseline

```bash
node packages/cli/dist/index.js compare \
  docs/examples/reports/baseline-safe.json \
  current.json \
  --fail-on-new-severity critical,high \
  --fail-on-category-regression
```

Compare output includes score delta, new/fixed/persistent breaches, new/resolved errors, changed confidence, category coverage changes, and gate failures.

## Boundaries

Eval Lab only scans endpoints you control or have permission to test. It does not execute tools on behalf of the target agent.
