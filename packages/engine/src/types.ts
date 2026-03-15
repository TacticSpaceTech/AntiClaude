// AntiClaude Engine - Core Type Definitions

export type OwaspCategory =
  | 'ASI01-agent-goal-hijack'
  | 'ASI02-tool-abuse'
  | 'ASI03-permission-abuse'
  | 'ASI04-supply-chain'
  | 'ASI05-code-execution'
  | 'ASI07-system-prompt-leak'
  | 'ASI08-human-agent-trust'

export type Severity = 'critical' | 'high' | 'medium' | 'low'

export type AttackStrategy =
  | 'direct'
  | 'encoding'
  | 'roleplay'
  | 'multilingual'
  | 'nested'
  | 'continuation'
  | 'fragmented'
  | 'semantic'

export interface DetectRule {
  type: 'contains_any' | 'not_contains' | 'regex' | 'length_above'
  values?: string[]
  pattern?: string
  threshold?: number
  weight: number
}

export interface PayloadDefinition {
  id: string
  info: {
    name: string
    severity: Severity
    category: OwaspCategory
    tags: string[]
    description?: string
  }
  attack: {
    type: 'single' | 'multi-turn'
    payload: string
    setup?: string
  }
  detect: {
    rules: DetectRule[]
    threshold: number
  }
  remediation?: string
}

export interface ScanResult {
  payloadId: string
  payloadName: string
  category: OwaspCategory
  severity: Severity
  prompt: string
  response: string
  fullResponse: string
  leaked: boolean
  confidence: number
  indicators: string[]
  strategy: AttackStrategy
  generation: number
  requestDuration: number
  error?: string
  judgeVerdict?: LlmJudgeVerdict
}

export interface OwaspCoverage {
  category: OwaspCategory
  label: string
  tested: number
  passed: number
  failed: number
  score: number
}

export interface ScanReport {
  id: string
  timestamp: string
  targetEndpoint: string
  duration: number
  results: ScanResult[]
  score: number
  owaspCoverage: OwaspCoverage[]
  summary: {
    totalPayloads: number
    totalAttempts: number
    breaches: number
    blocked: number
    errors: number
  }
}

export interface AttackVariant {
  id: string
  originalPayloadId: string
  strategy: AttackStrategy
  prompt: string
  description: string
  generation: number
}

export interface ScanProgress {
  type: 'init' | 'attack_start' | 'attack_result' | 'strategy_selected' | 'complete' | 'error'
  payload?: PayloadDefinition
  result?: ScanResult
  strategy?: AttackStrategy
  report?: ScanReport
  message?: string
  totalPayloads?: number
  currentIndex?: number
}

export interface ScanOptions {
  endpoint: string
  authHeader?: string
  payloadCount?: number
  maxVariants?: number
  timeout?: number
  onProgress?: (progress: ScanProgress) => void
  llmJudge?: LlmJudgeConfig
}

// Skill Auditor types

export interface SkillDefinition {
  name: string
  description: string
  parameters?: Record<string, unknown>
  capabilities?: string[]
  returnType?: string
  filePath?: string
}

export type AuditDimension =
  | 'description-poisoning'
  | 'parameter-injection'
  | 'permission-scope'
  | 'return-value-trust'
  | 'tool-shadowing'
  | 'integrity'

export interface SkillFinding {
  dimension: AuditDimension
  severity: Severity
  message: string
  evidence?: string
  recommendation: string
}

export interface SkillAuditResult {
  skill: SkillDefinition
  findings: SkillFinding[]
  score: number
  hash?: string
}

// LLM Judge types

export type LlmJudgeProvider = 'openai' | 'anthropic'

export interface LlmJudgeConfig {
  provider: LlmJudgeProvider
  apiKey: string
  model?: string
  confidenceRange?: [number, number]
  timeout?: number
}

export interface LlmJudgeVerdict {
  leaked: boolean
  confidence: number
  reasoning: string
}

// MCP Scanner types

export type McpAuditDimension =
  | 'credential-exposure'
  | 'command-injection'
  | 'dependency-integrity'
  | 'permission-escalation'
  | 'tool-description-poisoning'
  | 'source-validation'

export interface McpServerConfig {
  name: string
  command: string
  args?: string[]
  env?: Record<string, string>
  enabled?: boolean
  url?: string
  configPath: string
}

export interface McpFinding {
  dimension: McpAuditDimension
  severity: Severity
  serverName: string
  message: string
  evidence?: string
  recommendation: string
}

export interface McpScanResult {
  servers: McpServerConfig[]
  findings: McpFinding[]
  score: number
  configPaths: string[]
}
