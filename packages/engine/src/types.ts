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

export type TargetAdapter =
  | 'generic-json'
  | 'openai-chat'
  | 'anthropic-messages'
  | 'custom-json'

export interface TargetRequestConfig {
  adapter?: TargetAdapter
  authHeader?: string
  bodyField?: string
  bodyTemplate?: string
  model?: string
  maxTokens?: number
}

export interface TargetRequestEvidence {
  method: 'POST'
  url: string
  adapter: TargetAdapter
  headers: Record<string, string>
  body: unknown
}

export interface TargetMetadata {
  endpoint: string
  adapter: TargetAdapter
  bodyField?: string
  hasAuthHeader: boolean
  timeout: number
  payloadCount: number
  maxVariants: number
  model?: string
  maxTokens?: number
}

export interface ReproductionInfo {
  command: string
  config: Record<string, unknown>
}

export interface EvalSuiteConfig {
  name?: string
  description?: string
  seed?: string | number
  count?: number
  categories?: OwaspCategory[]
  severities?: Severity[]
  tags?: string[]
  payloadIds?: string[]
  maxVariants?: number
  expected?: {
    minBreaches?: number
    maxBreaches?: number
    minScore?: number
    maxScore?: number
  }
}

export interface EvalSuiteMetadata {
  name?: string
  description?: string
  seed?: string | number
  count?: number
  categories?: OwaspCategory[]
  severities?: Severity[]
  tags?: string[]
  payloadIds?: string[]
}

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
  owaspCategory: OwaspCategory
  severity: Severity
  prompt: string
  request: TargetRequestEvidence
  response: string
  fullResponse: string
  leaked: boolean
  status: 'breached' | 'blocked' | 'error'
  confidence: number
  confidenceSource: 'detector' | 'llm-judge' | 'none'
  indicators: string[]
  strategy: AttackStrategy
  generation: number
  requestDuration: number
  remediation?: string
  error?: string
  errorState?: string
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
  reportVersion: 1
  id: string
  timestamp: string
  targetEndpoint: string
  target: TargetMetadata
  suite?: EvalSuiteMetadata
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
  reproduction: ReproductionInfo
}

export interface CompareFinding {
  payloadId: string
  payloadName: string
  category: OwaspCategory
  severity: Severity
  strategy: AttackStrategy
  baselineStatus?: 'breached' | 'blocked' | 'error'
  currentStatus?: 'breached' | 'blocked' | 'error'
  baselineConfidence?: number
  currentConfidence?: number
}

export interface CompareCategoryCoverageChange {
  category: OwaspCategory
  label: string
  baselineScore: number
  currentScore: number
  delta: number
}

export interface CompareGateOptions {
  failOnScoreDrop?: number
  failOnNewBreachSeverity?: Severity[]
  failOnNewError?: boolean
  failOnCategoryRegression?: boolean
}

export interface CompareReport {
  compareVersion: 1
  baselineReportId: string
  currentReportId: string
  baselineScore: number
  currentScore: number
  scoreDelta: number
  newBreaches: CompareFinding[]
  fixedBreaches: CompareFinding[]
  persistentBreaches: CompareFinding[]
  newErrors: CompareFinding[]
  resolvedErrors: CompareFinding[]
  changedConfidence: CompareFinding[]
  categoryCoverageChanges: CompareCategoryCoverageChange[]
  gates: {
    failed: boolean
    failures: string[]
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
  target?: TargetRequestConfig
  suite?: EvalSuiteConfig
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
