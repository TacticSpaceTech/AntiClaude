import type { Metadata } from 'next'
import { SubPageHeader } from '@/components/sub-page-header'

export const metadata: Metadata = {
  title: 'Documentation - AntiClaude',
  description: 'AntiClaude documentation: CLI commands, runtime control, GitHub Action, engine library, and contributing guide.',
}

function SectionHeading({ id, children }: { id: string; children: React.ReactNode }) {
  return (
    <h2 id={id} className="text-2xl font-mono font-semibold text-foreground mt-14 mb-4 scroll-mt-24">
      <span className="text-primary/50">## </span>{children}
    </h2>
  )
}

function CodeBlock({ children }: { children: string }) {
  return (
    <pre className="bg-card/80 border border-border rounded-lg p-4 overflow-x-auto my-4">
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

function OptionsTable({ rows }: { rows: [string, string, string][] }) {
  return (
    <div className="overflow-x-auto my-4">
      <table className="w-full text-sm border border-border rounded-lg overflow-hidden">
        <thead>
          <tr className="bg-card/80 border-b border-border">
            <th className="text-left px-4 py-2 font-mono text-primary">Option</th>
            <th className="text-left px-4 py-2 font-mono text-primary">Default</th>
            <th className="text-left px-4 py-2 font-mono text-primary">Description</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(([option, defaultVal, desc], i) => (
            <tr key={i} className="border-b border-border/50 last:border-0">
              <td className="px-4 py-2 font-mono text-foreground whitespace-nowrap">{option}</td>
              <td className="px-4 py-2 text-muted-foreground whitespace-nowrap">{defaultVal}</td>
              <td className="px-4 py-2 text-muted-foreground">{desc}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default function DocsPage() {
  return (
    <div className="min-h-screen bg-background">
      <SubPageHeader active="/docs" />

      <main className="max-w-4xl mx-auto px-6 py-12 pb-24">
        <div className="mb-8">
          <p className="text-sm font-mono text-primary/60 mb-2">// documentation</p>
          <h1 className="text-4xl font-mono font-bold text-foreground mb-4">AntiClaude Docs</h1>
          <p className="text-muted-foreground leading-relaxed max-w-2xl">
            Everything you need to red-team your AI agents, test local runtime control,
            scan MCP configurations, and integrate security testing into your CI/CD pipeline.
          </p>
        </div>

        {/* Table of Contents */}
        <nav className="bg-card/80 border border-border rounded-lg p-4 mb-10">
          <p className="font-mono text-sm text-primary/70 mb-3">// contents</p>
          <ul className="space-y-1.5 text-sm">
            <li><a href="#quick-start" className="text-muted-foreground hover:text-primary transition-colors font-mono">01 Quick Start</a></li>
            <li><a href="#cli-commands" className="text-muted-foreground hover:text-primary transition-colors font-mono">02 CLI Commands</a></li>
            <li><a href="#control-plane" className="text-muted-foreground hover:text-primary transition-colors font-mono">03 Runtime Control Beta</a></li>
            <li><a href="#github-action" className="text-muted-foreground hover:text-primary transition-colors font-mono">04 GitHub Action</a></li>
            <li><a href="#engine-library" className="text-muted-foreground hover:text-primary transition-colors font-mono">05 Engine as Library</a></li>
            <li><a href="#contributing" className="text-muted-foreground hover:text-primary transition-colors font-mono">06 Contributing</a></li>
          </ul>
        </nav>

        {/* Quick Start */}
        <SectionHeading id="quick-start">Quick Start</SectionHeading>
        <p className="text-muted-foreground leading-relaxed mb-4">
          Scan any AI agent endpoint with a single command. No installation required.
        </p>
        <CodeBlock>
{`npx anticlaude scan \\
  --endpoint https://your-agent.example.com/api/chat \\
  --auth "Bearer sk-..." \\
  --count 20 \\
  --adapter generic-json \\
  --body-field message`}
        </CodeBlock>
        <p className="text-muted-foreground leading-relaxed mb-4">
          This sends randomized attack payloads to your endpoint, evaluates every response
          with deterministic detectors, and outputs an evidence-first report with a score out of 100.
          Add <InlineCode>--llm-judge openai</InlineCode> or <InlineCode>--llm-judge anthropic</InlineCode>
          when you want an optional semantic judge.
        </p>

        {/* CLI Commands */}
        <SectionHeading id="cli-commands">CLI Commands</SectionHeading>

        <h3 className="text-lg font-mono font-semibold text-foreground mt-8 mb-3">
          <InlineCode>scan</InlineCode>
        </h3>
        <p className="text-muted-foreground leading-relaxed mb-4">
          Run attack payloads against an AI agent endpoint.
        </p>
        <OptionsTable rows={[
          ['--endpoint', '(required)', 'Target agent API endpoint URL'],
          ['--auth', '""', 'Authorization header value (e.g. "Bearer sk-...")'],
          ['--adapter', 'generic-json', 'Request adapter: generic-json, openai-chat, anthropic-messages, custom-json'],
          ['--body-field', 'message', 'JSON field for the generic-json adapter'],
          ['--body-template', '""', 'Custom JSON request template using {{prompt}} or {{promptJson}}'],
          ['--target-model', '""', 'Model field for OpenAI-compatible or Anthropic-compatible APIs'],
          ['--suite', '""', 'Eval suite JSON file with deterministic payload selection'],
          ['--count', '12', 'Number of payloads to test'],
          ['--variants', '2', 'Max adaptive variants per payload'],
          ['--timeout', '15000', 'Request timeout in ms'],
          ['--output', 'markdown', 'Report format: json, markdown, html'],
          ['--out', '""', 'Write report to a file'],
          ['--fail-threshold', '""', 'Exit 1 if score is below this threshold'],
          ['--json-summary', 'false', 'Print ANTICLAUDE_SUMMARY for CI parsers'],
        ]} />

        <h3 className="text-lg font-mono font-semibold text-foreground mt-8 mb-3">
          <InlineCode>fixtures</InlineCode>
        </h3>
        <p className="text-muted-foreground leading-relaxed mb-4">
          Start deterministic local mock agents for eval lab runs.
        </p>
        <CodeBlock>
{`node packages/cli/dist/index.js fixtures --kind support-agent --port 4100`}
        </CodeBlock>

        <h3 className="text-lg font-mono font-semibold text-foreground mt-8 mb-3">
          <InlineCode>compare</InlineCode>
        </h3>
        <p className="text-muted-foreground leading-relaxed mb-4">
          Compare baseline and current JSON reports with local regression gates.
        </p>
        <CodeBlock>
{`npx anticlaude compare baseline.json current.json \\
  --fail-on-score-drop 10 \\
  --fail-on-new-severity critical,high \\
  --fail-on-new-error \\
  --fail-on-category-regression`}
        </CodeBlock>

        <h3 className="text-lg font-mono font-semibold text-foreground mt-8 mb-3">
          <InlineCode>audit</InlineCode>
        </h3>
        <p className="text-muted-foreground leading-relaxed mb-4">
          Audit a local skill or tool definition for poisoning, injection, permission scope,
          return-value trust, tool shadowing, and integrity risks.
        </p>
        <OptionsTable rows={[
          ['<path>', '(required)', 'Path to a skill file or directory'],
          ['--pin', 'false', 'Generate an .anticlaude-lock integrity file'],
          ['--lock', '""', 'Path to an existing integrity lock file'],
        ]} />

        <h3 className="text-lg font-mono font-semibold text-foreground mt-8 mb-3">
          <InlineCode>mcp-scan</InlineCode>
        </h3>
        <p className="text-muted-foreground leading-relaxed mb-4">
          Discover and audit MCP server configurations for credential exposure,
          command injection, dependency integrity, permission escalation, and source validation.
        </p>
        <OptionsTable rows={[
          ['--config', 'auto-discover', 'Explicit MCP config path; omit to scan known local config locations'],
          ['--project', '.', 'Project directory for local MCP config discovery'],
          ['--output', 'text', 'Output format: text, json, markdown'],
          ['--out', '""', 'Write report to a file'],
        ]} />

        <h3 className="text-lg font-mono font-semibold text-foreground mt-8 mb-3">
          <InlineCode>badge</InlineCode>
        </h3>
        <p className="text-muted-foreground leading-relaxed mb-4">
          Generate a security score badge SVG for your README.
        </p>
        <OptionsTable rows={[
          ['--score', '(required)', 'Security score (0-100)'],
          ['--output, -o', 'badge.svg', 'Output file path'],
        ]} />

        <h3 className="text-lg font-mono font-semibold text-foreground mt-8 mb-3">
          <InlineCode>guard</InlineCode>
        </h3>
        <p className="text-muted-foreground leading-relaxed mb-4">
          Start the local-only Guard alpha gateway for prompt, tool-call, and output policy decisions.
        </p>
        <CodeBlock>
{`npx anticlaude guard \\
  --config docs/examples/policies/anticlaude.policy.yaml \\
  --target http://127.0.0.1:4100/chat \\
  --trace traces/anticlaude-guard.jsonl \\
  --review-store reviews/anticlaude-reviews.jsonl`}
        </CodeBlock>

        <h3 className="text-lg font-mono font-semibold text-foreground mt-8 mb-3">
          <InlineCode>review</InlineCode>
        </h3>
        <p className="text-muted-foreground leading-relaxed mb-4">
          List, inspect, approve, or deny local runtime review requests.
        </p>
        <CodeBlock>
{`node packages/cli/dist/index.js review list --store reviews/anticlaude-reviews.jsonl
node packages/cli/dist/index.js review approve review_id --store reviews/anticlaude-reviews.jsonl --reason "Verified request"`}
        </CodeBlock>

        <h3 className="text-lg font-mono font-semibold text-foreground mt-8 mb-3">
          <InlineCode>replay</InlineCode>
        </h3>
        <p className="text-muted-foreground leading-relaxed mb-4">
          Replay local JSONL audit traces as a timeline.
        </p>
        <CodeBlock>
{`npx anticlaude replay docs/examples/traces/sample-trace.jsonl`}
        </CodeBlock>

        {/* Control Plane */}
        <SectionHeading id="control-plane">Runtime Control Beta</SectionHeading>
        <p className="text-muted-foreground leading-relaxed mb-4">
          The local web console at <InlineCode>/control-plane</InlineCode> loads committed example agents,
          tools, runtime profile, review queue, incidents, reports, comparisons, policy decisions, and trace data
          from this repo. It is an inspection surface for local artifacts, not a hosted dashboard.
        </p>
        <CodeBlock>
{`pnpm dev
open http://localhost:3000/control-plane`}
        </CodeBlock>

        {/* GitHub Action */}
        <SectionHeading id="github-action">GitHub Action</SectionHeading>
        <p className="text-muted-foreground leading-relaxed mb-4">
          Add AntiClaude to your CI/CD pipeline to catch security regressions automatically.
        </p>
        <CodeBlock>
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
          output-format: json
          baseline-report: docs/examples/reports/baseline-safe.json
          fail-on-new-severity: critical,high
          fail-on-category-regression: true
          count: 20
          fail-threshold: 70`}
        </CodeBlock>
        <p className="text-muted-foreground leading-relaxed mb-4">
          The action fails the workflow if the score drops below <InlineCode>fail-threshold</InlineCode>.
          It emits stable <InlineCode>score</InlineCode>, <InlineCode>breaches</InlineCode>,
          <InlineCode>errors</InlineCode>, and <InlineCode>report-path</InlineCode> outputs.
          When compare gates are enabled, it also emits <InlineCode>compare-path</InlineCode>.
        </p>

        {/* Engine as Library */}
        <SectionHeading id="engine-library">Engine as Library</SectionHeading>
        <p className="text-muted-foreground leading-relaxed mb-4">
          Use the AntiClaude engine programmatically in your own tools and test suites.
        </p>
        <CodeBlock>
{`npm install @anticlaude/engine`}
        </CodeBlock>
        <CodeBlock>
{`import {
  DEFAULT_GUARD_POLICY,
  DEFAULT_RUNTIME_POLICY_PROFILE,
  evaluateGuardPolicy,
  evaluateRuntimeToolRequest,
  runScan,
} from '@anticlaude/engine'

const report = await runScan({
  endpoint: 'https://your-agent.example.com/api/chat',
  target: {
    adapter: 'generic-json',
    bodyField: 'message',
    authHeader: 'Bearer sk-...',
  },
  payloadCount: 10,
  maxVariants: 2,
})

console.log(report.reportVersion)
console.log(report.score)
console.log(report.results[0].request.body)

const decision = evaluateGuardPolicy(DEFAULT_GUARD_POLICY, {
  surface: 'tool-call',
  toolCall: { name: 'refund_user', arguments: { amount: 9999 } },
})

console.log(decision.action)

const runtimeDecision = evaluateRuntimeToolRequest(DEFAULT_RUNTIME_POLICY_PROFILE, {
  agentId: 'support-agent',
  toolCall: { name: 'export_customer_data', arguments: { destination: 'external@example.com' } },
})

console.log(runtimeDecision.action)`}
        </CodeBlock>

        {/* Contributing */}
        <SectionHeading id="contributing">Contributing</SectionHeading>
        <p className="text-muted-foreground leading-relaxed mb-4">
          AntiClaude is open source under AGPL-3.0-only. We welcome contributions of all kinds:
          new payloads, engine improvements, documentation, and bug fixes.
        </p>
        <p className="text-muted-foreground leading-relaxed mb-4">
          Read the full contributing guide on GitHub:{' '}
          <a
            href="https://github.com/TacticSpaceTech/AntiClaude/blob/main/CONTRIBUTING.md"
            target="_blank"
            rel="noopener noreferrer"
            className="text-primary hover:underline"
          >
            CONTRIBUTING.md
          </a>
        </p>
      </main>
    </div>
  )
}
