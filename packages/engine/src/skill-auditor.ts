import * as fs from 'fs'
import * as path from 'path'
import * as crypto from 'crypto'
import * as yaml from 'js-yaml'
import type { SkillDefinition, SkillFinding, SkillAuditResult, AuditDimension, Severity } from './types'

// Dimension 1: Description Poisoning
function auditDescriptionPoisoning(skill: SkillDefinition): SkillFinding[] {
  const findings: SkillFinding[] = []
  const desc = skill.description.toLowerCase()

  const dangerousPatterns = [
    { pattern: /\b(must|always|never|required|mandatory)\b/i, msg: 'Imperative language in tool description' },
    { pattern: /\b(before|after|first|then)\s+(any|all|every|each)\b/i, msg: 'Sequencing instruction found' },
    { pattern: /\b(ignore|override|bypass|disregard|forget)\b/i, msg: 'Override directive in description' },
    { pattern: /\b(secret|hidden|internal|private|confidential)\b/i, msg: 'Secrecy language in description' },
    { pattern: /\b(output|print|reveal|display|show)\s+(your|the|all)\b/i, msg: 'Data exfiltration directive' },
    { pattern: /\b(system\s*prompt|instructions|configuration)\b/i, msg: 'References system internals' },
  ]

  for (const { pattern, msg } of dangerousPatterns) {
    const match = skill.description.match(pattern)
    if (match) {
      findings.push({
        dimension: 'description-poisoning',
        severity: desc.includes('ignore') || desc.includes('override') ? 'critical' : 'high',
        message: msg,
        evidence: `Found "${match[0]}" in description`,
        recommendation: 'Remove instructional language from tool descriptions. Descriptions should only explain what the tool does, not direct agent behavior.',
      })
    }
  }

  return findings
}

// Dimension 2: Parameter Injection
function auditParameterInjection(skill: SkillDefinition): SkillFinding[] {
  const findings: SkillFinding[] = []
  if (!skill.parameters) return findings

  function checkParams(params: Record<string, unknown>, prefix = '') {
    for (const [key, schema] of Object.entries(params)) {
      const s = schema as Record<string, unknown>
      if (s.type === 'string') {
        const issues: string[] = []
        if (!s.maxLength) issues.push('no maxLength')
        if (!s.pattern && !s.enum) issues.push('no pattern/enum constraint')

        if (issues.length > 0) {
          findings.push({
            dimension: 'parameter-injection',
            severity: issues.length >= 2 ? 'high' : 'medium',
            message: `Unconstrained string parameter: ${prefix}${key} (${issues.join(', ')})`,
            evidence: `Parameter "${prefix}${key}" has type "string" with ${issues.join(' and ')}`,
            recommendation: `Add constraints to "${prefix}${key}": maxLength, pattern regex, or enum values to prevent injection.`,
          })
        }
      }
      if (s.properties && typeof s.properties === 'object') {
        checkParams(s.properties as Record<string, unknown>, `${prefix}${key}.`)
      }
    }
  }

  const props = (skill.parameters as Record<string, unknown>).properties
  if (props && typeof props === 'object') {
    checkParams(props as Record<string, unknown>)
  }

  return findings
}

// Dimension 3: Permission Scope
function auditPermissionScope(skill: SkillDefinition): SkillFinding[] {
  const findings: SkillFinding[] = []
  if (!skill.capabilities || skill.capabilities.length === 0) return findings

  const highRiskCaps = ['filesystem', 'network', 'execute', 'shell', 'admin', 'root', 'sudo', 'database', 'credentials']

  for (const cap of skill.capabilities) {
    if (highRiskCaps.some(h => cap.toLowerCase().includes(h))) {
      findings.push({
        dimension: 'permission-scope',
        severity: 'high',
        message: `High-risk capability declared: "${cap}"`,
        evidence: `Tool "${skill.name}" requests "${cap}" capability`,
        recommendation: `Review if "${cap}" is strictly necessary. Apply principle of least privilege.`,
      })
    }
  }

  if (skill.capabilities.length > 3) {
    findings.push({
      dimension: 'permission-scope',
      severity: 'medium',
      message: `Excessive capabilities: ${skill.capabilities.length} requested`,
      evidence: `Capabilities: ${skill.capabilities.join(', ')}`,
      recommendation: 'Reduce capability set to the minimum required for this tool\'s function.',
    })
  }

  return findings
}

// Dimension 4: Return Value Trust
function auditReturnValueTrust(skill: SkillDefinition): SkillFinding[] {
  const findings: SkillFinding[] = []

  if (!skill.returnType || skill.returnType === 'string' || skill.returnType === 'any') {
    findings.push({
      dimension: 'return-value-trust',
      severity: 'medium',
      message: `Untyped or loosely typed return value: "${skill.returnType || 'unspecified'}"`,
      evidence: `Tool "${skill.name}" return type is "${skill.returnType || 'unspecified'}"`,
      recommendation: 'Define a specific return type schema. Mark return values as untrusted if they contain user-generated content.',
    })
  }

  return findings
}

// Dimension 5: Tool Shadowing
function auditToolShadowing(skill: SkillDefinition): SkillFinding[] {
  const findings: SkillFinding[] = []

  const wellKnownTools = [
    'read_file', 'write_file', 'execute', 'run_command', 'search', 'browse',
    'send_email', 'send_message', 'http_request', 'fetch', 'database_query',
    'get_user', 'authenticate', 'authorize', 'shell', 'terminal', 'code_interpreter',
  ]

  const name = skill.name.toLowerCase().replace(/[-_\s]/g, '')

  for (const known of wellKnownTools) {
    const knownNorm = known.replace(/[-_\s]/g, '')
    const distance = levenshtein(name, knownNorm)
    if (distance > 0 && distance <= 2) {
      findings.push({
        dimension: 'tool-shadowing',
        severity: 'critical',
        message: `Tool name "${skill.name}" is similar to known tool "${known}" (edit distance: ${distance})`,
        evidence: `Levenshtein distance between "${name}" and "${knownNorm}" is ${distance}`,
        recommendation: `Rename tool to avoid confusion with "${known}". Similar names can trick agents into calling malicious tools.`,
      })
    }
  }

  return findings
}

// Dimension 6: Integrity
function auditIntegrity(skill: SkillDefinition, lockFilePath?: string): SkillFinding[] {
  const findings: SkillFinding[] = []

  if (!skill.filePath || !fs.existsSync(skill.filePath)) return findings

  const content = fs.readFileSync(skill.filePath, 'utf-8')
  const hash = crypto.createHash('sha256').update(content).digest('hex')

  if (lockFilePath && fs.existsSync(lockFilePath)) {
    const lock = JSON.parse(fs.readFileSync(lockFilePath, 'utf-8')) as Record<string, string>
    const expected = lock[skill.name]
    if (expected && expected !== hash) {
      findings.push({
        dimension: 'integrity',
        severity: 'critical',
        message: `Integrity check failed for "${skill.name}"`,
        evidence: `Expected hash ${expected.slice(0, 16)}..., got ${hash.slice(0, 16)}...`,
        recommendation: 'Tool file has been modified since last pin. Review changes and run `anticlaude audit --pin` to update.',
      })
    }
  }

  return findings
}

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

export function auditSkill(skill: SkillDefinition, lockFilePath?: string): SkillAuditResult {
  const findings: SkillFinding[] = [
    ...auditDescriptionPoisoning(skill),
    ...auditParameterInjection(skill),
    ...auditPermissionScope(skill),
    ...auditReturnValueTrust(skill),
    ...auditToolShadowing(skill),
    ...auditIntegrity(skill, lockFilePath),
  ]

  const severityScores: Record<Severity, number> = { critical: 30, high: 20, medium: 10, low: 5 }
  let penalty = 0
  for (const f of findings) penalty += severityScores[f.severity]
  const score = Math.max(0, 100 - penalty)

  let hash: string | undefined
  if (skill.filePath && fs.existsSync(skill.filePath)) {
    const content = fs.readFileSync(skill.filePath, 'utf-8')
    hash = crypto.createHash('sha256').update(content).digest('hex')
  }

  return { skill, findings, score, hash }
}

export function auditSkills(skills: SkillDefinition[], lockFilePath?: string): SkillAuditResult[] {
  return skills.map(s => auditSkill(s, lockFilePath))
}

export function parseSkillFiles(dirPath: string): SkillDefinition[] {
  const skills: SkillDefinition[] = []

  if (!fs.existsSync(dirPath)) return skills

  const stat = fs.statSync(dirPath)
  const files = stat.isDirectory()
    ? fs.readdirSync(dirPath).filter((f: string) => f.endsWith('.json') || f.endsWith('.yaml') || f.endsWith('.yml')).map((f: string) => path.join(dirPath, f))
    : [dirPath]

  for (const file of files) {
    try {
      const content = fs.readFileSync(file, 'utf-8')
      let parsed: unknown

      if (file.endsWith('.json')) {
        parsed = JSON.parse(content)
      } else {
        parsed = yaml.load(content)
      }

      if (parsed && typeof parsed === 'object') {
        const obj = parsed as Record<string, unknown>
        // Handle MCP-style tool definition
        if (obj.name && obj.description) {
          skills.push({
            name: obj.name as string,
            description: obj.description as string,
            parameters: obj.parameters as Record<string, unknown> | undefined,
            capabilities: obj.capabilities as string[] | undefined,
            returnType: obj.returnType as string | undefined,
            filePath: file,
          })
        }
        // Handle array of tools
        if (Array.isArray(obj.tools)) {
          for (const tool of obj.tools) {
            if (tool.name && tool.description) {
              skills.push({
                name: tool.name,
                description: tool.description,
                parameters: tool.parameters,
                capabilities: tool.capabilities,
                returnType: tool.returnType,
                filePath: file,
              })
            }
          }
        }
      }
    } catch {
      // Skip unparseable files
    }
  }

  return skills
}

export function generateLockFile(results: SkillAuditResult[]): Record<string, string> {
  const lock: Record<string, string> = {}
  for (const r of results) {
    if (r.hash) lock[r.skill.name] = r.hash
  }
  return lock
}
