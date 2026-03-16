import React from 'react'

export interface BlogPost {
  slug: string
  title: string
  date: string
  description: string
  readingTime: string
  content: React.ReactNode
}

function Code({ children, block }: { children: React.ReactNode; block?: boolean }) {
  if (block) {
    return (
      <pre className="bg-card/80 border border-border rounded-lg p-4 overflow-x-auto my-4">
        <code className="text-sm font-mono text-primary">{children}</code>
      </pre>
    )
  }
  return (
    <code className="bg-card/80 border border-border rounded px-1.5 py-0.5 text-sm font-mono text-primary">
      {children}
    </code>
  )
}

function H2({ children }: { children: React.ReactNode }) {
  return <h2 className="text-2xl font-mono font-semibold text-foreground mt-10 mb-4">{children}</h2>
}

function H3({ children }: { children: React.ReactNode }) {
  return <h3 className="text-xl font-mono font-semibold text-foreground mt-8 mb-3">{children}</h3>
}

function P({ children }: { children: React.ReactNode }) {
  return <p className="text-muted-foreground leading-relaxed mb-4">{children}</p>
}

function A({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
      {children}
    </a>
  )
}

function Ul({ children }: { children: React.ReactNode }) {
  return <ul className="list-disc list-inside space-y-2 text-muted-foreground mb-4 ml-2">{children}</ul>
}

export const posts: BlogPost[] = [
  {
    slug: 'introducing-anticlaude',
    title: 'Introducing AntiClaude: Open-Source Red-Teaming for AI Agents',
    date: '2026-03-17',
    description: 'AntiClaude v1.0 is now available on npm. 64 attack payloads, 7 OWASP categories, LLM Judge, MCP Scanner.',
    readingTime: '5 min read',
    content: (
      <>
        <P>
          Today we are releasing AntiClaude v1.0 &mdash; an open-source red-teaming toolkit purpose-built
          for AI agents, MCP servers, and LLM-powered applications. It is available on npm right now.
        </P>

        <H2>Why AntiClaude?</H2>
        <P>
          AI agents are being deployed into production at an unprecedented pace. They read emails,
          execute code, manage databases, and interact with third-party APIs. Yet most teams have
          no systematic way to test whether their agent can be tricked into leaking secrets,
          executing unauthorized actions, or bypassing its own safety guardrails.
        </P>
        <P>
          AntiClaude fills that gap. It ships with 64 carefully crafted attack payloads spanning
          7 of the OWASP Agentic Top 10 categories, an LLM-based judge for accurate leak detection,
          and a dedicated MCP server configuration scanner.
        </P>

        <H2>Quick Start</H2>
        <P>
          You can scan any agent endpoint in a single command:
        </P>
        <Code block>
{`npx anticlaude scan \\
  --endpoint https://your-agent.example.com/api/chat \\
  --auth "Bearer sk-..." \\
  --payloads 20`}
        </Code>
        <P>
          This sends a randomized selection of payloads to your endpoint, evaluates every response
          with the LLM judge, and produces a security score with detailed findings.
        </P>

        <H2>Key Features</H2>
        <Ul>
          <li><strong className="text-foreground">64 attack payloads</strong> covering prompt injection, privilege escalation, data exfiltration, and more</li>
          <li><strong className="text-foreground">LLM Judge</strong> that analyzes responses for actual information leaks, not just keyword matching</li>
          <li><strong className="text-foreground">MCP Scanner</strong> that audits MCP server configs for hardcoded secrets, unpinned packages, and shell injection</li>
          <li><strong className="text-foreground">GitHub Action</strong> for CI/CD integration</li>
          <li><strong className="text-foreground">Web UI</strong> for interactive scanning at anticlaude.dev</li>
          <li><strong className="text-foreground">Engine as library</strong> &mdash; <Code>npm install @anticlaude/engine</Code> for programmatic use</li>
        </Ul>

        <H2>OWASP Coverage</H2>
        <P>
          AntiClaude currently covers 7 out of 10 categories from the OWASP Agentic Security Top 10:
          prompt injection, excessive agency, system prompt leakage, insecure output handling,
          data exfiltration, privilege escalation, and supply chain vulnerabilities (via MCP scanning).
        </P>

        <H2>Open Source</H2>
        <P>
          AntiClaude is licensed under AGPL-3.0. The entire codebase &mdash; payloads, engine,
          CLI, and web app &mdash; lives in a single monorepo on GitHub.
        </P>
        <P>
          <A href="https://github.com/TacticSpaceTech/AntiClaude">View on GitHub</A> &middot;{' '}
          <A href="https://www.npmjs.com/package/anticlaude">Install from npm</A>
        </P>
      </>
    ),
  },
  {
    slug: 'owasp-agentic-top-10-guide',
    title: 'Understanding the OWASP Agentic Top 10',
    date: '2026-03-17',
    description: 'A practical guide to the 10 most critical security risks for AI agents, and how AntiClaude tests for them.',
    readingTime: '8 min read',
    content: (
      <>
        <P>
          The OWASP Agentic Security Initiative published the Agentic Top 10 to catalog the most
          critical security risks facing AI agent deployments. This post walks through each category,
          explains why it matters, and notes which ones AntiClaude currently tests for.
        </P>

        <H2>ASI01 &mdash; Prompt Injection</H2>
        <P>
          An attacker embeds instructions in user input (or in data the agent retrieves) that override
          the system prompt. This is the most common and most dangerous class of agent vulnerability.
        </P>
        <P>
          <strong className="text-primary">AntiClaude coverage:</strong> Yes. Multiple payload families
          including direct injection, indirect injection via tool output simulation, and multi-turn
          escalation sequences.
        </P>

        <H2>ASI02 &mdash; Excessive Agency / Privilege Escalation</H2>
        <P>
          The agent has access to more tools or permissions than it needs. An attacker tricks it into
          using those capabilities &mdash; deleting files, sending emails, modifying databases &mdash;
          beyond its intended scope.
        </P>
        <P>
          <strong className="text-primary">AntiClaude coverage:</strong> Yes. Payloads attempt to
          invoke admin-level operations, change configuration, and access resources outside the
          agent&apos;s stated role.
        </P>

        <H2>ASI03 &mdash; System Prompt Leakage</H2>
        <P>
          The agent reveals its system prompt, internal instructions, or configuration when prompted.
          This gives attackers a blueprint for more targeted attacks.
        </P>
        <P>
          <strong className="text-primary">AntiClaude coverage:</strong> Yes. Dedicated extraction
          payloads using role-play, translation tricks, encoding schemes, and meta-prompting.
        </P>

        <H2>ASI04 &mdash; Tool / Function Call Manipulation</H2>
        <P>
          An attacker manipulates the agent into calling tools with attacker-controlled parameters,
          such as crafting malicious SQL through a database tool or injecting shell commands through
          a code execution tool.
        </P>
        <P>
          <strong className="text-primary">AntiClaude coverage:</strong> Partial. Tested indirectly
          through prompt injection payloads that attempt to invoke tools with modified parameters.
        </P>

        <H2>ASI05 &mdash; Insecure Output Handling</H2>
        <P>
          The agent&apos;s output is rendered in a context where it can cause harm &mdash; XSS in a
          web UI, command injection in a terminal, or markdown rendering exploits.
        </P>
        <P>
          <strong className="text-primary">AntiClaude coverage:</strong> Yes. Payloads that attempt
          to inject HTML, markdown links, and script tags through the agent&apos;s responses.
        </P>

        <H2>ASI06 &mdash; Data Exfiltration</H2>
        <P>
          The agent is tricked into sending sensitive data to an external endpoint, embedding it in
          URLs, or including it in responses that get logged or forwarded.
        </P>
        <P>
          <strong className="text-primary">AntiClaude coverage:</strong> Yes. Payloads that instruct
          the agent to include internal data in markdown images, external API calls, or encoded
          output channels.
        </P>

        <H2>ASI07 &mdash; Denial of Service</H2>
        <P>
          An attacker causes the agent to consume excessive resources &mdash; infinite loops, massive
          context windows, or expensive tool calls &mdash; making it unavailable to legitimate users.
        </P>
        <P>
          <strong className="text-primary">AntiClaude coverage:</strong> Not currently tested.
          Future versions may include resource-consumption probes.
        </P>

        <H2>ASI08 &mdash; Insecure Memory / RAG Poisoning</H2>
        <P>
          If the agent has persistent memory or retrieves from a vector store, an attacker can
          inject malicious content that persists across sessions or affects other users.
        </P>
        <P>
          <strong className="text-primary">AntiClaude coverage:</strong> Not currently tested.
          Requires stateful interaction patterns.
        </P>

        <H2>ASI09 &mdash; Supply Chain Vulnerabilities</H2>
        <P>
          The agent relies on third-party models, plugins, or MCP servers that may themselves be
          compromised, misconfigured, or malicious.
        </P>
        <P>
          <strong className="text-primary">AntiClaude coverage:</strong> Yes. The <Code>mcp-scan</Code> command
          audits MCP server configurations for hardcoded secrets, unpinned package versions, shell
          injection vectors, and overly broad permissions.
        </P>

        <H2>ASI10 &mdash; Insufficient Logging and Monitoring</H2>
        <P>
          The system does not adequately log agent actions, making it impossible to detect or
          investigate attacks after the fact.
        </P>
        <P>
          <strong className="text-primary">AntiClaude coverage:</strong> Not directly tested, but
          AntiClaude&apos;s scan output itself serves as a monitoring artifact that teams can review.
        </P>

        <H2>Summary</H2>
        <P>
          AntiClaude currently covers 7 of the 10 OWASP Agentic categories with active payloads.
          The remaining three (DoS, memory poisoning, and logging gaps) are on the roadmap.
          Running <Code>npx anticlaude scan</Code> against your agent is one of the fastest ways
          to assess your exposure across these categories.
        </P>
      </>
    ),
  },
  {
    slug: 'mcp-server-security',
    title: 'Why Your MCP Server Configuration Might Be Leaking Secrets',
    date: '2026-03-17',
    description: 'MCP configs often contain hardcoded API keys, unpinned packages, and shell injection vectors. Here\'s how to audit them.',
    readingTime: '6 min read',
    content: (
      <>
        <P>
          The Model Context Protocol (MCP) has quickly become the standard way to connect AI agents
          to external tools and data sources. But with rapid adoption comes a pattern we see
          repeatedly: MCP server configurations that leak secrets, use unpinned dependencies,
          or are vulnerable to shell injection.
        </P>

        <H2>Common Issues We Find</H2>

        <H3>1. Hardcoded API Keys</H3>
        <P>
          The most common issue. MCP configs are JSON or YAML files that specify how to launch
          and connect to tool servers. Many developers put API keys directly in these files:
        </P>
        <Code block>
{`{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "ghp_xxxxxxxxxxxxxxxxxxxx"
      }
    }
  }
}`}
        </Code>
        <P>
          If this file is committed to version control, checked into a dotfiles repo, or backed up
          to cloud storage, those keys are exposed. AntiClaude&apos;s MCP scanner flags every
          environment variable value that matches known secret patterns (API keys, tokens, passwords).
        </P>

        <H3>2. Unpinned Package Versions</H3>
        <P>
          Using <Code>npx -y @some/package</Code> without a version pin means you are running
          whatever the latest version happens to be at execution time. A supply chain attack
          on that package would immediately compromise your agent.
        </P>
        <Code block>
{`// Dangerous: runs latest version, whatever it may be
"command": "npx",
"args": ["-y", "@modelcontextprotocol/server-github"]

// Better: pin to a specific version
"command": "npx",
"args": ["-y", "@modelcontextprotocol/server-github@1.2.3"]`}
        </Code>

        <H3>3. Shell Injection via Arguments</H3>
        <P>
          Some MCP configs use shell commands with string interpolation or pass user-controllable
          data into command arguments. If the agent can influence which MCP server gets called
          or what arguments are passed, this can lead to arbitrary command execution.
        </P>

        <H3>4. Overly Broad Permissions</H3>
        <P>
          MCP servers often request (or are granted) more filesystem, network, or API permissions
          than they actually need. A read-only documentation tool should not have write access to
          your filesystem.
        </P>

        <H2>How anticlaude mcp-scan Works</H2>
        <P>
          The <Code>mcp-scan</Code> command reads your MCP configuration file and performs static
          analysis on every server definition:
        </P>
        <Code block>
{`npx anticlaude mcp-scan --config ~/.cursor/mcp.json`}
        </Code>
        <P>
          It checks for:
        </P>
        <Ul>
          <li>Hardcoded secrets in environment variables (pattern-matched against 20+ known formats)</li>
          <li>Unpinned npm packages in npx commands</li>
          <li>Shell metacharacters in command arguments</li>
          <li>Known vulnerable package versions</li>
          <li>Overly permissive server configurations</li>
        </Ul>
        <P>
          The output is a structured report with severity levels and remediation suggestions for
          each finding.
        </P>

        <H2>Example Output</H2>
        <Code block>
{`MCP Configuration Audit
=======================
File: /Users/dev/.cursor/mcp.json

[CRITICAL] github-server
  Hardcoded secret in env.GITHUB_TOKEN
  Unpinned package: @modelcontextprotocol/server-github

[WARNING] filesystem-server
  Broad path access: /Users/dev (consider restricting to project dir)

[INFO] sqlite-server
  Package version pinned: @modelcontextprotocol/server-sqlite@1.0.2

Score: 45/100 - Needs attention`}
        </Code>

        <H2>Recommendations</H2>
        <Ul>
          <li>Use environment variable references instead of hardcoded values</li>
          <li>Pin every package to a specific version and review before updating</li>
          <li>Restrict filesystem and network access to the minimum required scope</li>
          <li>Run <Code>npx anticlaude mcp-scan</Code> in CI to catch regressions</li>
          <li>Audit your MCP config every time you add a new server</li>
        </Ul>

        <P>
          MCP is a powerful protocol, but power without guardrails is a liability. Take five
          minutes to audit your configuration today.
        </P>
        <P>
          <A href="https://github.com/TacticSpaceTech/AntiClaude">Get AntiClaude on GitHub</A>
        </P>
      </>
    ),
  },
]
