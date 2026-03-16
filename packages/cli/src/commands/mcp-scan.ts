import { Command } from 'commander'
import chalk from 'chalk'
import * as fs from 'fs'
import { discoverMcpConfigs, auditMcpServers, mcpReportToMarkdown } from '@anticlaude/engine'
import type { McpScanResult } from '@anticlaude/engine'

function severityColor(severity: string): string {
  switch (severity) {
    case 'critical': return chalk.red.bold(severity.toUpperCase())
    case 'high': return chalk.red(severity.toUpperCase())
    case 'medium': return chalk.yellow(severity.toUpperCase())
    case 'low': return chalk.green(severity.toUpperCase())
    default: return severity
  }
}

function dimensionLabel(dim: string): string {
  const labels: Record<string, string> = {
    'credential-exposure': 'Credential Exposure',
    'command-injection': 'Command Injection',
    'dependency-integrity': 'Dependency Integrity',
    'permission-escalation': 'Permission Escalation',
    'tool-description-poisoning': 'Tool Poisoning',
    'source-validation': 'Source Validation',
  }
  return labels[dim] || dim
}

export const mcpScanCommand = new Command('mcp-scan')
  .description('Discover and audit MCP server configurations for security issues')
  .option('--config <path>', 'Path to specific MCP config file')
  .option('--project <dir>', 'Project directory for local config discovery', '.')
  .option('--output <format>', 'Output format: text, json, markdown', 'text')
  .option('--out <file>', 'Write report to file')
  .action(async (opts) => {
    console.log('')
    console.log(chalk.green.bold('  ╔═══════════════════════════════════╗'))
    console.log(chalk.green.bold('  ║') + chalk.white.bold('    AntiClaude MCP Scanner        ') + chalk.green.bold('║'))
    console.log(chalk.green.bold('  ╚═══════════════════════════════════╝'))
    console.log('')

    let servers
    if (opts.config) {
      if (!fs.existsSync(opts.config)) {
        console.log(chalk.red(`  Error: Config file not found: ${opts.config}`))
        process.exit(1)
      }
      const { discoverMcpConfigs: discover } = await import('@anticlaude/engine')
      // Parse the specific file by temporarily importing the parser
      const allServers = discover()
      // Re-discover but filter by the specific config path
      servers = discoverMcpConfigs(opts.project)
      // Actually, let's just use the config path directly
      const configContent = fs.readFileSync(opts.config, 'utf-8')
      const parsed = JSON.parse(configContent)
      const serversObj = parsed.mcpServers || parsed.servers || parsed
      servers = Object.entries(serversObj).map(([name, config]: [string, any]) => ({
        name,
        command: String(config.command || ''),
        args: Array.isArray(config.args) ? config.args.map(String) : undefined,
        env: config.env && typeof config.env === 'object' ? config.env : undefined,
        enabled: config.enabled !== false,
        url: typeof config.url === 'string' ? config.url : undefined,
        configPath: opts.config,
      }))
    } else {
      servers = discoverMcpConfigs(opts.project)
    }

    if (servers.length === 0) {
      console.log(chalk.yellow('  No MCP server configurations found.'))
      console.log(chalk.dim('  Searched: ~/.cursor/mcp.json, ~/.claude/claude_desktop_config.json'))
      if (opts.project !== '.') {
        console.log(chalk.dim(`  Also searched project: ${opts.project}`))
      }
      console.log('')
      process.exit(0)
    }

    console.log(chalk.dim(`  Found ${servers.length} MCP server(s)`))
    console.log('')

    const result = auditMcpServers(servers)

    printResult(result)

    if (opts.out) {
      let content: string
      switch (opts.output) {
        case 'json':
          content = JSON.stringify(result, null, 2)
          break
        case 'markdown':
          content = mcpReportToMarkdown(result)
          break
        default:
          content = mcpReportToMarkdown(result)
      }
      fs.writeFileSync(opts.out, content, 'utf-8')
      console.log(chalk.dim(`  Report written to ${opts.out}`))
      console.log('')
    }
  })

function printResult(result: McpScanResult) {
  // Per-server results
  for (const server of result.servers) {
    const serverFindings = result.findings.filter(f => f.serverName === server.name)
    const status = serverFindings.length === 0
      ? chalk.green('✓ SAFE')
      : chalk.red(`✗ ${serverFindings.length} issue(s)`)

    console.log(`  ${chalk.white.bold(server.name)} — ${status}`)
    console.log(chalk.dim(`    ${server.command} ${(server.args || []).join(' ')}`))
    console.log(chalk.dim(`    from: ${server.configPath}`))

    for (const f of serverFindings) {
      console.log(
        `    ${severityColor(f.severity)} ` +
        chalk.dim(`[${dimensionLabel(f.dimension)}] `) +
        f.message
      )
      if (f.evidence) {
        console.log(chalk.dim(`      Evidence: ${f.evidence}`))
      }
      console.log(chalk.dim(`      Fix: ${f.recommendation}`))
    }
    console.log('')
  }

  // Summary
  const scoreStr = result.score >= 80
    ? chalk.green.bold(`${result.score}/100`)
    : result.score >= 50
    ? chalk.yellow.bold(`${result.score}/100`)
    : chalk.red.bold(`${result.score}/100`)

  console.log(chalk.green.bold('  ─── Summary ───'))
  console.log('')
  console.log(`  Score:    ${scoreStr}`)
  console.log(`  Servers:  ${result.servers.length}`)
  console.log(`  Findings: ${result.findings.length > 0 ? chalk.red.bold(String(result.findings.length)) : chalk.green('0')}`)
  console.log(`  Configs:  ${result.configPaths.join(', ')}`)
  console.log('')
}
