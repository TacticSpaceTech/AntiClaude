import type { Metadata } from 'next'
import { SubPageHeader } from '@/components/sub-page-header'

export const metadata: Metadata = {
  title: 'CI/CD Integration — AntiClaude',
  description: 'Integrate AntiClaude into your CI/CD pipeline with GitHub Actions, CLI tooling, fail thresholds, and LLM judge for automated AI agent security testing.',
}

function SectionHeading({ id, children }: { id: string; children: React.ReactNode }) {
  return (
    <h2 id={id} className="text-2xl font-mono font-semibold text-foreground mt-14 mb-4 scroll-mt-24">
      <span className="text-primary/50">## </span>{children}
    </h2>
  )
}

function CodeBlock({ lang, children }: { lang?: string; children: string }) {
  return (
    <pre className="bg-card/80 border border-border rounded-lg p-4 overflow-x-auto my-4">
      {lang && (
        <div className="text-xs font-mono text-muted-foreground mb-2">{lang}</div>
      )}
      <code className="text-sm font-mono text-primary">{children}</code>
    </pre>
  )
}

function InlineCode({ children }: { children: React.ReactNode }) {
  return (
    <code className="bg-card/80 border border-border rounded px-1.5 py-0.5 text-sm font-mono text-primary">
      {children}
    </code>
  )
}

function OptionsTable({ headers, rows }: { headers: string[]; rows: string[][] }) {
  return (
    <div className="overflow-x-auto my-4">
      <table className="w-full text-sm border border-border rounded-lg overflow-hidden">
        <thead>
          <tr className="bg-card/80 border-b border-border">
            {headers.map((h, i) => (
              <th key={i} className="text-left px-4 py-2 font-mono text-primary">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i} className="border-b border-border/50 last:border-0">
              {row.map((cell, j) => (
                <td key={j} className={`px-4 py-2 ${j === 0 ? 'font-mono text-foreground whitespace-nowrap' : 'text-muted-foreground'}`}>
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default function CicdPage() {
  return (
    <div className="min-h-screen bg-background">
      <SubPageHeader active="/cicd" />

      <main className="max-w-4xl mx-auto px-6 py-12 pb-24">
        <div className="mb-8">
          <p className="text-sm font-mono text-primary/60 mb-2">// continuous security</p>
          <h1 className="text-4xl font-mono font-bold text-foreground mb-4">
            Integrate AntiClaude into Your CI/CD Pipeline
          </h1>
          <p className="text-muted-foreground leading-relaxed max-w-2xl">
            Catch AI agent security regressions on every push and pull request.
            Block vulnerable configurations before they reach production.
          </p>
        </div>

        {/* Table of Contents */}
        <nav className="bg-card/80 border border-border rounded-lg p-4 mb-10">
          <p className="font-mono text-sm text-primary/70 mb-3">// contents</p>
          <ul className="space-y-1.5 text-sm">
            <li><a href="#github-action" className="text-muted-foreground hover:text-primary transition-colors font-mono">01 GitHub Action</a></li>
            <li><a href="#cli-in-ci" className="text-muted-foreground hover:text-primary transition-colors font-mono">02 CLI in CI</a></li>
            <li><a href="#compare-gates" className="text-muted-foreground hover:text-primary transition-colors font-mono">03 Compare Gates</a></li>
            <li><a href="#fail-thresholds" className="text-muted-foreground hover:text-primary transition-colors font-mono">04 Fail Thresholds</a></li>
            <li><a href="#llm-judge" className="text-muted-foreground hover:text-primary transition-colors font-mono">05 LLM Judge in CI</a></li>
          </ul>
        </nav>

        {/* GitHub Action */}
        <SectionHeading id="github-action">GitHub Action</SectionHeading>
        <p className="text-muted-foreground leading-relaxed mb-4">
          The fastest way to add AntiClaude to your pipeline. Drop the action into any workflow
          and it will scan your agent endpoint, post results as a PR comment, and fail the
          check if the score is below your threshold.
        </p>
        <CodeBlock lang="yaml">
{`# .github/workflows/security.yml
name: AI Agent Security Scan
on:
  push:
    branches: [main]
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run AntiClaude scan
        uses: TacticSpaceTech/AntiClaude/action@v1
        with:
          endpoint: \${{ secrets.AGENT_ENDPOINT }}
          auth: \${{ secrets.AGENT_AUTH }}
          count: 20
          adapter: generic-json
          output-format: json
          baseline-report: docs/security/baseline.json
          fail-on-new-severity: critical,high
          fail-on-category-regression: true
          fail-threshold: 70
          comment-on-pr: true`}
        </CodeBlock>

        <h3 className="text-lg font-mono font-semibold text-foreground mt-8 mb-3">Inputs</h3>
        <OptionsTable
          headers={['Input', 'Required', 'Default', 'Description']}
          rows={[
            ['endpoint', 'Yes', '—', 'Target agent API endpoint URL'],
            ['auth', 'No', '""', 'Authorization header value'],
            ['adapter', 'No', 'generic-json', 'Request adapter: generic-json, openai-chat, anthropic-messages, custom-json'],
            ['body-field', 'No', 'message', 'JSON field used by generic-json'],
            ['body-template', 'No', '—', 'Custom JSON template for custom-json'],
            ['target-model', 'No', '—', 'Model field for provider-compatible adapters'],
            ['suite', 'No', '—', 'Eval suite JSON file with deterministic payload selection'],
            ['count', 'No', '12', 'Number of payloads to test'],
            ['variants', 'No', '2', 'Max adaptive variants per payload'],
            ['fail-threshold', 'No', '70', 'Minimum passing score (0-100)'],
            ['baseline-report', 'No', '—', 'Baseline JSON report for compare gates; requires output-format=json'],
            ['fail-on-score-drop', 'No', '—', 'Fail if score drops by more than this many points'],
            ['fail-on-new-severity', 'No', '—', 'Fail on new breaches at comma-separated severities'],
            ['fail-on-new-error', 'No', 'false', 'Fail if current report has new errors'],
            ['fail-on-category-regression', 'No', 'false', 'Fail if any OWASP category score regresses'],
            ['comment-on-pr', 'No', 'true', 'Post results as a PR comment'],
            ['llm-judge', 'No', '—', 'LLM judge provider: openai or anthropic'],
          ]}
        />

        <h3 className="text-lg font-mono font-semibold text-foreground mt-8 mb-3">Outputs</h3>
        <OptionsTable
          headers={['Output', 'Type', 'Description']}
          rows={[
            ['score', 'number', 'Overall security score (0-100)'],
            ['breaches', 'number', 'Number of detected breaches'],
            ['errors', 'number', 'Number of request errors'],
            ['report-path', 'string', 'Path to the generated report file'],
            ['compare-path', 'string', 'Path to compare report JSON when baseline-report is set'],
          ]}
        />

        <p className="text-muted-foreground leading-relaxed mt-4">
          When <InlineCode>comment-on-pr</InlineCode> is enabled, the action posts a summary
          directly on your pull request showing the score, tested categories, and any
          findings.
        </p>

        {/* CLI in CI */}
        <SectionHeading id="cli-in-ci">CLI in CI</SectionHeading>
        <p className="text-muted-foreground leading-relaxed mb-4">
          For non-GitHub environments (GitLab CI, CircleCI, Jenkins, etc.) or custom pipelines,
          use the AntiClaude CLI directly. No installation step needed with <InlineCode>npx</InlineCode>.
        </p>
        <CodeBlock lang="bash">
{`npx anticlaude scan \\
  --endpoint $AGENT_URL \\
  --auth "Bearer $AGENT_TOKEN" \\
  --count 20 \\
  --output json \\
  --out report.json \\
  --json-summary`}
        </CodeBlock>

        <h3 className="text-lg font-mono font-semibold text-foreground mt-8 mb-3">Exit codes</h3>
        <OptionsTable
          headers={['Code', 'Meaning']}
          rows={[
            ['0', 'Scan completed and, when --fail-threshold is set, score met the threshold'],
            ['1', 'Bad arguments, scan failure, or score below --fail-threshold'],
          ]}
        />

        <h3 className="text-lg font-mono font-semibold text-foreground mt-8 mb-3">Parsing the JSON report</h3>
        <p className="text-muted-foreground leading-relaxed mb-4">
          The JSON report can be parsed in subsequent CI steps to extract specific fields,
          gate local workflows, or feed into your own internal reporting.
        </p>
        <CodeBlock lang="bash">
{`# Extract score from report
SCORE=$(jq '.score' report.json)
echo "Security score: $SCORE"

# Check for critical findings
CRITICAL=$(jq '[.results[] | select(.severity == "critical")] | length' report.json)
if [ "$CRITICAL" -gt 0 ]; then
  echo "Found $CRITICAL critical vulnerabilities"
  exit 1
fi`}
        </CodeBlock>

        {/* Compare Gates */}
        <SectionHeading id="compare-gates">Compare Gates</SectionHeading>
        <p className="text-muted-foreground leading-relaxed mb-4">
          Compare gates catch regressions against a committed baseline report. They require JSON reports.
        </p>
        <CodeBlock lang="bash">
{`npx anticlaude compare baseline.json current.json \\
  --fail-on-score-drop 10 \\
  --fail-on-new-severity critical,high \\
  --fail-on-new-error \\
  --fail-on-category-regression`}
        </CodeBlock>

        {/* Fail Thresholds */}
        <SectionHeading id="fail-thresholds">Fail Thresholds</SectionHeading>
        <p className="text-muted-foreground leading-relaxed mb-4">
          Use <InlineCode>--fail-threshold</InlineCode> to define the minimum acceptable security score.
          If the scan result falls below this value, the CLI exits with code 1, failing your
          CI pipeline and blocking the merge.
        </p>
        <CodeBlock lang="bash">
{`# Block PR if score drops below 70
npx anticlaude scan \\
  --endpoint $AGENT_URL \\
  --fail-threshold 70

# Stricter threshold for production branches
npx anticlaude scan \\
  --endpoint $AGENT_URL \\
  --fail-threshold 85 \\
  --count 40`}
        </CodeBlock>
        <p className="text-muted-foreground leading-relaxed mb-4">
          Recommended thresholds:
        </p>
        <OptionsTable
          headers={['Environment', 'Threshold', 'Rationale']}
          rows={[
            ['Development', '50', 'Catch obvious issues early without blocking iteration'],
            ['Staging', '70', 'Ensure reasonable security posture before QA'],
            ['Production', '85+', 'High bar for any agent facing real users'],
          ]}
        />

        {/* LLM Judge in CI */}
        <SectionHeading id="llm-judge">LLM Judge in CI</SectionHeading>
        <p className="text-muted-foreground leading-relaxed mb-4">
          By default, AntiClaude uses pattern matching to evaluate agent responses. For
          significantly higher accuracy, enable the LLM judge. This uses an LLM to analyze
          whether the agent leaked sensitive information, followed instructions from injected
          prompts, or otherwise failed security checks.
        </p>
        <CodeBlock lang="bash">
{`npx anticlaude scan \\
  --endpoint $AGENT_URL \\
  --llm-judge openai \\
  --fail-threshold 70`}
        </CodeBlock>
        <p className="text-muted-foreground leading-relaxed mb-4">
          The LLM judge requires an API key. Store it as a CI secret and pass it via
          environment variable:
        </p>
        <CodeBlock lang="yaml">
{`# GitHub Actions example
env:
  OPENAI_API_KEY: \${{ secrets.OPENAI_API_KEY }}

steps:
  - name: Run AntiClaude with LLM Judge
    uses: TacticSpaceTech/AntiClaude/action@v1
    with:
      endpoint: \${{ secrets.AGENT_ENDPOINT }}
      auth: \${{ secrets.AGENT_AUTH }}
      llm-judge: openai
      llm-key: \${{ secrets.OPENAI_API_KEY }}
      fail-threshold: 70`}
        </CodeBlock>
        <p className="text-muted-foreground leading-relaxed mb-4">
          The LLM judge adds latency (roughly 1-2 seconds per payload) but catches subtle
          information leaks and indirect prompt-injection failures that pattern matching
          may miss. Consider enabling it for higher-signal staging checks.
        </p>

        <div className="bg-card/80 border border-primary/30 rounded-lg p-5 mt-10">
          <p className="font-mono text-sm text-primary mb-2">// tip</p>
          <p className="text-muted-foreground text-sm leading-relaxed">
            Combine <InlineCode>--llm-judge</InlineCode> with a higher payload count
            for broader coverage. Runtime depends on target latency and judge provider
            latency, so keep CI timeouts explicit.
          </p>
        </div>
      </main>
    </div>
  )
}
