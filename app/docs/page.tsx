import type { Metadata } from 'next'
import Link from 'next/link'

export const metadata: Metadata = {
  title: 'Documentation - AntiClaude',
  description: 'AntiClaude documentation: CLI commands, GitHub Action, engine library, and contributing guide.',
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
      <header className="border-b border-primary/20 bg-background/90 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-4xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2.5 hover:opacity-80 transition-opacity">
            <img src="/icon-192x192.png" alt="AntiClaude" className="w-8 h-8 rounded" />
            <span className="font-semibold text-primary text-lg font-mono">AntiClaude</span>
          </Link>
          <Link href="/" className="text-sm text-muted-foreground hover:text-foreground transition-colors font-mono">
            &larr; Home
          </Link>
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-6 py-12 pb-24">
        <div className="mb-8">
          <p className="text-sm font-mono text-primary/60 mb-2">// documentation</p>
          <h1 className="text-4xl font-mono font-bold text-foreground mb-4">AntiClaude Docs</h1>
          <p className="text-muted-foreground leading-relaxed max-w-2xl">
            Everything you need to red-team your AI agents, scan MCP configurations,
            and integrate security testing into your CI/CD pipeline.
          </p>
        </div>

        {/* Table of Contents */}
        <nav className="bg-card/80 border border-border rounded-lg p-4 mb-10">
          <p className="font-mono text-sm text-primary/70 mb-3">// contents</p>
          <ul className="space-y-1.5 text-sm">
            <li><a href="#quick-start" className="text-muted-foreground hover:text-primary transition-colors font-mono">01 Quick Start</a></li>
            <li><a href="#cli-commands" className="text-muted-foreground hover:text-primary transition-colors font-mono">02 CLI Commands</a></li>
            <li><a href="#github-action" className="text-muted-foreground hover:text-primary transition-colors font-mono">03 GitHub Action</a></li>
            <li><a href="#engine-library" className="text-muted-foreground hover:text-primary transition-colors font-mono">04 Engine as Library</a></li>
            <li><a href="#contributing" className="text-muted-foreground hover:text-primary transition-colors font-mono">05 Contributing</a></li>
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
  --payloads 20`}
        </CodeBlock>
        <p className="text-muted-foreground leading-relaxed mb-4">
          This sends 20 randomized attack payloads to your endpoint, evaluates every response
          with the LLM judge, and outputs a security report with a score out of 100.
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
          ['--endpoint, -e', '(required)', 'Target agent API endpoint URL'],
          ['--auth, -a', '""', 'Authorization header value (e.g. "Bearer sk-...")'],
          ['--payloads, -p', '6', 'Number of payloads to send (max 64)'],
          ['--categories, -c', 'all', 'OWASP categories to test (comma-separated)'],
          ['--severity', 'all', 'Filter by severity: low, medium, high, critical'],
          ['--output, -o', 'stdout', 'Output file path for JSON report'],
          ['--threshold', '70', 'Minimum passing score (exit 1 if below)'],
        ]} />

        <h3 className="text-lg font-mono font-semibold text-foreground mt-8 mb-3">
          <InlineCode>audit</InlineCode>
        </h3>
        <p className="text-muted-foreground leading-relaxed mb-4">
          Perform a comprehensive audit combining scan + mcp-scan with a unified report.
        </p>
        <OptionsTable rows={[
          ['--endpoint, -e', '(required)', 'Target agent API endpoint URL'],
          ['--config', '""', 'MCP config file to include in audit'],
          ['--auth, -a', '""', 'Authorization header value'],
          ['--output, -o', 'stdout', 'Output file path for JSON report'],
        ]} />

        <h3 className="text-lg font-mono font-semibold text-foreground mt-8 mb-3">
          <InlineCode>mcp-scan</InlineCode>
        </h3>
        <p className="text-muted-foreground leading-relaxed mb-4">
          Audit an MCP server configuration file for security issues.
        </p>
        <OptionsTable rows={[
          ['--config', '(required)', 'Path to MCP configuration JSON file'],
          ['--output, -o', 'stdout', 'Output file path for JSON report'],
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
        uses: TacticSpaceTech/anticlaude-action@v1
        with:
          endpoint: \${{ secrets.AGENT_ENDPOINT }}
          auth: \${{ secrets.AGENT_AUTH }}
          payloads: 20
          threshold: 70`}
        </CodeBlock>
        <p className="text-muted-foreground leading-relaxed mb-4">
          The action will fail the workflow if the security score drops below the threshold,
          preventing vulnerable agent configurations from reaching production.
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
{`import { loadPayloads, runAttack, judge } from '@anticlaude/engine'

// Load all payloads (or filter by category/severity)
const payloads = loadPayloads({
  categories: ['prompt-injection', 'data-exfiltration'],
  count: 10
})

// Run an attack against your endpoint
for (const payload of payloads) {
  const response = await runAttack({
    endpoint: 'https://your-agent.example.com/api/chat',
    payload,
    auth: 'Bearer sk-...',
  })

  // Judge the response for information leaks
  const result = await judge(payload, response)
  console.log(\`\${payload.name}: \${result.leaked ? 'LEAKED' : 'SAFE'}\`)
}`}
        </CodeBlock>

        {/* Contributing */}
        <SectionHeading id="contributing">Contributing</SectionHeading>
        <p className="text-muted-foreground leading-relaxed mb-4">
          AntiClaude is open source under AGPL-3.0. We welcome contributions of all kinds:
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
