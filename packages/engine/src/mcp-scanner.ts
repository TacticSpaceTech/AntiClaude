import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import type { McpServerConfig, McpFinding, McpScanResult, McpAuditDimension, Severity } from './types'

const MCP_CONFIG_PATHS = [
  { base: 'home', rel: '.cursor/mcp.json' },
  { base: 'home', rel: '.claude/claude_desktop_config.json' },
]

const PROJECT_CONFIG_PATHS = [
  '.cursor/mcp.json',
  '.vscode/mcp.json',
]

function parseMcpConfigFile(filePath: string): McpServerConfig[] {
  try {
    const content = fs.readFileSync(filePath, 'utf-8')
    const parsed = JSON.parse(content) as Record<string, unknown>
    const serversObj = (parsed.mcpServers ?? parsed.servers ?? parsed) as Record<string, unknown>

    if (typeof serversObj !== 'object' || serversObj === null) return []

    const servers: McpServerConfig[] = []
    for (const [name, config] of Object.entries(serversObj)) {
      if (!config || typeof config !== 'object') continue
      const c = config as Record<string, unknown>
      if (!c.command && !c.url) continue
      servers.push({
        name,
        command: String(c.command || ''),
        args: Array.isArray(c.args) ? c.args.map(String) : undefined,
        env: c.env && typeof c.env === 'object' ? c.env as Record<string, string> : undefined,
        enabled: c.enabled !== false,
        url: typeof c.url === 'string' ? c.url : undefined,
        configPath: filePath,
      })
    }
    return servers
  } catch {
    return []
  }
}

export function discoverMcpConfigs(projectDir?: string): McpServerConfig[] {
  const servers: McpServerConfig[] = []
  const homeDir = os.homedir()

  for (const { base, rel } of MCP_CONFIG_PATHS) {
    const fullPath = base === 'home' ? path.join(homeDir, rel) : rel
    if (fs.existsSync(fullPath)) {
      servers.push(...parseMcpConfigFile(fullPath))
    }
  }

  if (projectDir) {
    for (const rel of PROJECT_CONFIG_PATHS) {
      const fullPath = path.join(projectDir, rel)
      if (fs.existsSync(fullPath)) {
        servers.push(...parseMcpConfigFile(fullPath))
      }
    }
  }

  return servers
}

// Dimension 1: Credential Exposure
const SECRET_PATTERNS = [
  /^sk-[a-zA-Z0-9]{20,}/,
  /^ghp_[a-zA-Z0-9]{36}/,
  /^ghs_[a-zA-Z0-9]{36}/,
  /^glpat-[a-zA-Z0-9\-_]{20,}/,
  /^xox[bpsa]-[a-zA-Z0-9\-]{10,}/,
  /^eyJ[a-zA-Z0-9\-_]+\.eyJ/,
  /^[a-zA-Z0-9+/]{40,}={0,2}$/,
  /^AKIA[0-9A-Z]{16}/,
  /^sbp_[a-zA-Z0-9]{20,}/,
  /^figd_[a-zA-Z0-9]{20,}/,
]

const SECRET_FLAG_PATTERNS = [
  /--(?:api[_-]?key|token|secret|password|credentials?|auth)[=\s]/i,
  /--(?:access[_-]?token|auth[_-]?token)[=\s]/i,
]

function checkCredentialExposure(server: McpServerConfig): McpFinding[] {
  const findings: McpFinding[] = []

  if (server.env) {
    for (const [key, value] of Object.entries(server.env)) {
      for (const pattern of SECRET_PATTERNS) {
        if (pattern.test(value)) {
          findings.push({
            dimension: 'credential-exposure',
            severity: 'critical',
            serverName: server.name,
            message: `Hardcoded secret in env var "${key}"`,
            evidence: `${key}=${value.slice(0, 8)}...`,
            recommendation: 'Use environment variable references or a secrets manager instead of hardcoding credentials.',
          })
          break
        }
      }
    }
  }

  if (server.args) {
    const argsStr = server.args.join(' ')
    for (const pattern of SECRET_FLAG_PATTERNS) {
      if (pattern.test(argsStr)) {
        findings.push({
          dimension: 'credential-exposure',
          severity: 'high',
          serverName: server.name,
          message: 'Credential passed via command-line argument',
          evidence: `args contain secret flag pattern`,
          recommendation: 'Pass credentials via environment variables instead of command-line arguments.',
        })
        break
      }
    }
  }

  return findings
}

// Dimension 2: Command Injection
function checkCommandInjection(server: McpServerConfig): McpFinding[] {
  const findings: McpFinding[] = []

  const shellCommands = ['sh', 'bash', 'zsh', 'cmd', 'powershell', 'pwsh']
  const cmdBase = path.basename(server.command)
  if (shellCommands.includes(cmdBase)) {
    const hasExecFlag = server.args?.some(a => a === '-c' || a === '/c')
    if (hasExecFlag) {
      findings.push({
        dimension: 'command-injection',
        severity: 'critical',
        serverName: server.name,
        message: `Shell execution via "${server.command} -c"`,
        evidence: `command: ${server.command}, args contain -c flag`,
        recommendation: 'Avoid shell execution. Use direct binary invocation instead of shell -c wrappers.',
      })
    }
  }

  if (server.args) {
    const dangerousPatterns = [/\$\(/, /`[^`]+`/, /&&/, /\|\|/, /;/, /\|/]
    for (const arg of server.args) {
      for (const pattern of dangerousPatterns) {
        if (pattern.test(arg)) {
          findings.push({
            dimension: 'command-injection',
            severity: 'high',
            serverName: server.name,
            message: 'Shell metacharacter in args',
            evidence: `Suspicious arg: "${arg.slice(0, 50)}"`,
            recommendation: 'Remove shell metacharacters from arguments. Each argument should be a plain value.',
          })
          return findings
        }
      }
    }
  }

  return findings
}

// Dimension 3: Dependency Integrity
function checkDependencyIntegrity(server: McpServerConfig): McpFinding[] {
  const findings: McpFinding[] = []
  if (!server.args) return findings

  for (const arg of server.args) {
    if (arg.includes('@latest')) {
      findings.push({
        dimension: 'dependency-integrity',
        severity: 'high',
        serverName: server.name,
        message: 'Unpinned dependency version (@latest)',
        evidence: `arg: "${arg}"`,
        recommendation: 'Pin to a specific version (e.g., package@1.2.3) to prevent supply chain attacks.',
      })
    }

    if (arg.match(/^https?:\/\//) || arg.startsWith('file:') || arg.startsWith('git+')) {
      findings.push({
        dimension: 'dependency-integrity',
        severity: 'medium',
        serverName: server.name,
        message: 'Non-registry package source',
        evidence: `arg: "${arg.slice(0, 80)}"`,
        recommendation: 'Prefer packages from the official npm registry. Verify external sources before use.',
      })
    }
  }

  // Check if npx is used without a version pin
  if (['npx', 'pnpx', 'bunx'].includes(path.basename(server.command))) {
    const pkgArg = server.args.find(a => !a.startsWith('-') && !a.startsWith('--'))
    if (pkgArg && !pkgArg.includes('@') && !pkgArg.startsWith('.') && !pkgArg.startsWith('/')) {
      findings.push({
        dimension: 'dependency-integrity',
        severity: 'high',
        serverName: server.name,
        message: `Unpinned package via ${path.basename(server.command)}: "${pkgArg}"`,
        evidence: `No version specified for "${pkgArg}"`,
        recommendation: `Pin version: "${pkgArg}@x.y.z" to prevent executing unexpected code.`,
      })
    }
  }

  return findings
}

// Dimension 4: Permission Escalation
function checkPermissionEscalation(server: McpServerConfig): McpFinding[] {
  const findings: McpFinding[] = []

  if (server.command === 'sudo' || server.command.endsWith('/sudo')) {
    findings.push({
      dimension: 'permission-escalation',
      severity: 'critical',
      serverName: server.name,
      message: 'MCP server runs with sudo privileges',
      evidence: `command: ${server.command}`,
      recommendation: 'Never run MCP servers with elevated privileges. Use minimal permissions.',
    })
  }

  if (server.args) {
    const escalationFlags = ['--privileged', '--root', '--admin', '--no-sandbox']
    for (const arg of server.args) {
      if (escalationFlags.some(f => arg.toLowerCase() === f)) {
        findings.push({
          dimension: 'permission-escalation',
          severity: 'high',
          serverName: server.name,
          message: `Privilege escalation flag: "${arg}"`,
          evidence: `arg: "${arg}"`,
          recommendation: 'Remove privilege escalation flags. Apply principle of least privilege.',
        })
      }
    }
  }

  return findings
}

// Dimension 5: Tool Description Poisoning
const POISONING_PATTERNS = [
  { pattern: /\b(ignore|override|bypass|disregard|forget)\b/i, msg: 'Override directive in description' },
  { pattern: /\b(must|always|never|required|mandatory)\b/i, msg: 'Imperative language in description' },
  { pattern: /\b(secret|hidden|internal|private|confidential)\b/i, msg: 'Secrecy language in description' },
  { pattern: /\b(output|print|reveal|display|show)\s+(your|the|all)\b/i, msg: 'Data exfiltration directive' },
  { pattern: /\b(system\s*prompt|instructions|configuration)\b/i, msg: 'References system internals' },
]

function checkToolDescriptionPoisoning(server: McpServerConfig): McpFinding[] {
  const findings: McpFinding[] = []

  // Check args for embedded instructions
  if (server.args) {
    const argsStr = server.args.join(' ')
    for (const { pattern, msg } of POISONING_PATTERNS) {
      const match = argsStr.match(pattern)
      if (match) {
        findings.push({
          dimension: 'tool-description-poisoning',
          severity: argsStr.toLowerCase().includes('ignore') || argsStr.toLowerCase().includes('override') ? 'critical' : 'high',
          serverName: server.name,
          message: msg,
          evidence: `Found "${match[0]}" in args`,
          recommendation: 'Remove instructional language from MCP server arguments.',
        })
        break
      }
    }
  }

  return findings
}

// Dimension 6: Source Validation
const WELL_KNOWN_MCP_PACKAGES = [
  'mcp-server', 'modelcontextprotocol', '@modelcontextprotocol',
  'claude-mcp', 'mcp-tool', 'mcp-bridge',
]

function levenshtein(a: string, b: string): number {
  const m = a.length
  const n = b.length
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0))
  for (let i = 0; i <= m; i++) dp[i][0] = i
  for (let j = 0; j <= n; j++) dp[0][j] = j
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])
    }
  }
  return dp[m][n]
}

function checkSourceValidation(server: McpServerConfig): McpFinding[] {
  const findings: McpFinding[] = []
  if (!server.args) return findings

  const pkgArgs = server.args.filter(a => !a.startsWith('-') && !a.startsWith('/'))
  for (const arg of pkgArgs) {
    const pkgName = arg.split('@')[0].toLowerCase()
    if (!pkgName || pkgName.length < 3) continue

    for (const known of WELL_KNOWN_MCP_PACKAGES) {
      const distance = levenshtein(pkgName, known)
      if (distance > 0 && distance <= 2) {
        findings.push({
          dimension: 'source-validation',
          severity: 'high',
          serverName: server.name,
          message: `Package "${pkgName}" is similar to known package "${known}" (typosquatting risk)`,
          evidence: `Levenshtein distance: ${distance}`,
          recommendation: `Verify the package name. Did you mean "${known}"?`,
        })
      }
    }
  }

  return findings
}

export function auditMcpServer(server: McpServerConfig): McpFinding[] {
  return [
    ...checkCredentialExposure(server),
    ...checkCommandInjection(server),
    ...checkDependencyIntegrity(server),
    ...checkPermissionEscalation(server),
    ...checkToolDescriptionPoisoning(server),
    ...checkSourceValidation(server),
  ]
}

export function auditMcpServers(servers: McpServerConfig[]): McpScanResult {
  const findings: McpFinding[] = []
  const configPaths = [...new Set(servers.map(s => s.configPath))]

  for (const server of servers) {
    findings.push(...auditMcpServer(server))
  }

  const severityScores: Record<Severity, number> = { critical: 30, high: 20, medium: 10, low: 5 }
  let penalty = 0
  for (const f of findings) penalty += severityScores[f.severity]
  const score = Math.max(0, 100 - penalty)

  return { servers, findings, score, configPaths }
}

export function mcpReportToMarkdown(result: McpScanResult): string {
  const lines: string[] = [
    '# AntiClaude MCP Security Scan Report',
    '',
    `**Score:** ${result.score}/100`,
    `**Servers scanned:** ${result.servers.length}`,
    `**Findings:** ${result.findings.length}`,
    `**Config files:** ${result.configPaths.join(', ')}`,
    '',
  ]

  if (result.findings.length === 0) {
    lines.push('No security issues found.')
  } else {
    lines.push('## Findings', '')
    for (const f of result.findings) {
      lines.push(`### [${f.severity.toUpperCase()}] ${f.serverName}: ${f.message}`)
      lines.push(`- **Dimension:** ${f.dimension}`)
      if (f.evidence) lines.push(`- **Evidence:** ${f.evidence}`)
      lines.push(`- **Recommendation:** ${f.recommendation}`)
      lines.push('')
    }
  }

  return lines.join('\n')
}
