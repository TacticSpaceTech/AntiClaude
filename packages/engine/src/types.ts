// AntiClaude Engine - Core Type Definitions

export type OwaspCategory =
  | 'ASI01-agent-goal-hijack'
  | 'ASI02-tool-abuse'
  | 'ASI04-supply-chain'
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
