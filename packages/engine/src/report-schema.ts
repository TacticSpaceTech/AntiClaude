import type { ScanReport } from './types'

export interface ReportValidationResult {
  valid: boolean
  errors: string[]
}

const OWASP_CATEGORIES = [
  'ASI01-agent-goal-hijack',
  'ASI02-tool-abuse',
  'ASI03-permission-abuse',
  'ASI04-supply-chain',
  'ASI05-code-execution',
  'ASI07-system-prompt-leak',
  'ASI08-human-agent-trust',
]

const SEVERITIES = ['critical', 'high', 'medium', 'low']
const ATTACK_STRATEGIES = ['direct', 'encoding', 'roleplay', 'multilingual', 'nested', 'continuation', 'fragmented', 'semantic']
const TARGET_ADAPTERS = ['generic-json', 'openai-chat', 'anthropic-messages', 'custom-json']
const RESULT_STATUSES = ['breached', 'blocked', 'error']
const CONFIDENCE_SOURCES = ['detector', 'llm-judge', 'none']

export function validateScanReport(report: unknown): ReportValidationResult {
  const errors: string[] = []
  if (!isObject(report)) return { valid: false, errors: ['report must be an object'] }

  expectEqual(report, 'reportVersion', 1, errors)
  expectString(report, 'id', errors)
  expectString(report, 'timestamp', errors)
  expectString(report, 'targetEndpoint', errors)
  expectNumber(report, 'duration', errors)
  expectNumber(report, 'score', errors)

  validateTarget(report.target, errors)
  validateSuite(report.suite, errors)

  if (!Array.isArray(report.results)) {
    errors.push('results must be an array')
  } else {
    report.results.forEach((result, index) => validateResult(result, `results[${index}]`, errors))
  }

  if (!Array.isArray(report.owaspCoverage)) {
    errors.push('owaspCoverage must be an array')
  } else {
    report.owaspCoverage.forEach((coverage, index) => validateCoverage(coverage, `owaspCoverage[${index}]`, errors))
  }

  if (!isObject(report.summary)) {
    errors.push('summary must be an object')
  } else {
    for (const field of ['totalPayloads', 'totalAttempts', 'breaches', 'blocked', 'errors']) {
      expectNumber(report.summary, field, errors, `summary.${field}`)
    }
  }

  validateReproduction(report.reproduction, errors)

  return { valid: errors.length === 0, errors }
}

export function assertValidScanReport(report: unknown): asserts report is ScanReport {
  const result = validateScanReport(report)
  if (!result.valid) {
    throw new Error(`Invalid AntiClaude report: ${result.errors.join('; ')}`)
  }
}

function validateTarget(target: unknown, errors: string[]): void {
  if (!isObject(target)) {
    errors.push('target must be an object')
    return
  }

  expectString(target, 'endpoint', errors, 'target.endpoint')
  expectOneOf(target, 'adapter', TARGET_ADAPTERS, errors, 'target.adapter')
  expectBoolean(target, 'hasAuthHeader', errors, 'target.hasAuthHeader')
  expectNumber(target, 'timeout', errors, 'target.timeout')
  expectNumber(target, 'payloadCount', errors, 'target.payloadCount')
  expectNumber(target, 'maxVariants', errors, 'target.maxVariants')
  expectOptionalString(target, 'bodyField', errors, 'target.bodyField')
  expectOptionalString(target, 'model', errors, 'target.model')
  expectOptionalNumber(target, 'maxTokens', errors, 'target.maxTokens')
}

function validateSuite(suite: unknown, errors: string[]): void {
  if (suite === undefined) return
  if (!isObject(suite)) {
    errors.push('suite must be an object')
    return
  }

  expectOptionalString(suite, 'name', errors, 'suite.name')
  expectOptionalString(suite, 'description', errors, 'suite.description')
  if (suite.seed !== undefined && typeof suite.seed !== 'string' && typeof suite.seed !== 'number') {
    errors.push('suite.seed must be a string or number')
  }
  expectOptionalNumber(suite, 'count', errors, 'suite.count')
  expectOptionalStringArray(suite, 'payloadIds', errors, 'suite.payloadIds')
  expectOptionalOneOfArray(suite, 'categories', OWASP_CATEGORIES, errors, 'suite.categories')
  expectOptionalOneOfArray(suite, 'severities', SEVERITIES, errors, 'suite.severities')
  expectOptionalStringArray(suite, 'tags', errors, 'suite.tags')
}

function validateResult(result: unknown, prefix: string, errors: string[]): void {
  if (!isObject(result)) {
    errors.push(`${prefix} must be an object`)
    return
  }

  for (const field of ['payloadId', 'payloadName', 'prompt', 'response', 'fullResponse']) {
    expectString(result, field, errors, `${prefix}.${field}`)
  }
  expectOneOf(result, 'category', OWASP_CATEGORIES, errors, `${prefix}.category`)
  expectOneOf(result, 'owaspCategory', OWASP_CATEGORIES, errors, `${prefix}.owaspCategory`)
  expectOneOf(result, 'severity', SEVERITIES, errors, `${prefix}.severity`)
  expectOneOf(result, 'status', RESULT_STATUSES, errors, `${prefix}.status`)
  expectOneOf(result, 'confidenceSource', CONFIDENCE_SOURCES, errors, `${prefix}.confidenceSource`)
  expectOneOf(result, 'strategy', ATTACK_STRATEGIES, errors, `${prefix}.strategy`)
  expectBoolean(result, 'leaked', errors, `${prefix}.leaked`)
  expectNumber(result, 'confidence', errors, `${prefix}.confidence`)
  expectNumber(result, 'generation', errors, `${prefix}.generation`)
  expectNumber(result, 'requestDuration', errors, `${prefix}.requestDuration`)
  expectStringArray(result, 'indicators', errors, `${prefix}.indicators`)
  expectOptionalString(result, 'remediation', errors, `${prefix}.remediation`)
  expectOptionalString(result, 'error', errors, `${prefix}.error`)
  expectOptionalString(result, 'errorState', errors, `${prefix}.errorState`)
  validateJudgeVerdict(result.judgeVerdict, `${prefix}.judgeVerdict`, errors)

  if (!isObject(result.request)) {
    errors.push(`${prefix}.request must be an object`)
  } else {
    expectEqual(result.request, 'method', 'POST', errors, `${prefix}.request.method`)
    expectString(result.request, 'url', errors, `${prefix}.request.url`)
    expectOneOf(result.request, 'adapter', TARGET_ADAPTERS, errors, `${prefix}.request.adapter`)
    if (!isObject(result.request.headers)) errors.push(`${prefix}.request.headers must be an object`)
    if (!('body' in result.request)) errors.push(`${prefix}.request.body is required`)
  }
}

function validateCoverage(coverage: unknown, prefix: string, errors: string[]): void {
  if (!isObject(coverage)) {
    errors.push(`${prefix} must be an object`)
    return
  }

  expectOneOf(coverage, 'category', OWASP_CATEGORIES, errors, `${prefix}.category`)
  expectString(coverage, 'label', errors, `${prefix}.label`)
  for (const field of ['tested', 'passed', 'failed', 'score']) {
    expectNumber(coverage, field, errors, `${prefix}.${field}`)
  }
}

function validateReproduction(reproduction: unknown, errors: string[]): void {
  if (!isObject(reproduction)) {
    errors.push('reproduction must be an object')
    return
  }

  expectString(reproduction, 'command', errors, 'reproduction.command')
  if (!isObject(reproduction.config)) errors.push('reproduction.config must be an object')
}

function validateJudgeVerdict(verdict: unknown, prefix: string, errors: string[]): void {
  if (verdict === undefined) return
  if (!isObject(verdict)) {
    errors.push(`${prefix} must be an object`)
    return
  }

  expectBoolean(verdict, 'leaked', errors, `${prefix}.leaked`)
  expectNumber(verdict, 'confidence', errors, `${prefix}.confidence`)
  expectString(verdict, 'reasoning', errors, `${prefix}.reasoning`)
}

function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value)
}

function expectString(obj: Record<string, unknown>, field: string, errors: string[], label = field): void {
  if (typeof obj[field] !== 'string') errors.push(`${label} must be a string`)
}

function expectNumber(obj: Record<string, unknown>, field: string, errors: string[], label = field): void {
  if (typeof obj[field] !== 'number') errors.push(`${label} must be a number`)
}

function expectBoolean(obj: Record<string, unknown>, field: string, errors: string[], label = field): void {
  if (typeof obj[field] !== 'boolean') errors.push(`${label} must be a boolean`)
}

function expectEqual(obj: Record<string, unknown>, field: string, expected: unknown, errors: string[], label = field): void {
  if (obj[field] !== expected) errors.push(`${label} must be ${String(expected)}`)
}

function expectOneOf(obj: Record<string, unknown>, field: string, allowed: string[], errors: string[], label = field): void {
  if (typeof obj[field] !== 'string' || !allowed.includes(obj[field])) {
    errors.push(`${label} must be one of: ${allowed.join(', ')}`)
  }
}

function expectStringArray(obj: Record<string, unknown>, field: string, errors: string[], label = field): void {
  if (!Array.isArray(obj[field]) || obj[field].some(value => typeof value !== 'string')) {
    errors.push(`${label} must be an array of strings`)
  }
}

function expectOptionalString(obj: Record<string, unknown>, field: string, errors: string[], label = field): void {
  if (obj[field] !== undefined && typeof obj[field] !== 'string') errors.push(`${label} must be a string`)
}

function expectOptionalNumber(obj: Record<string, unknown>, field: string, errors: string[], label = field): void {
  if (obj[field] !== undefined && typeof obj[field] !== 'number') errors.push(`${label} must be a number`)
}

function expectOptionalStringArray(obj: Record<string, unknown>, field: string, errors: string[], label = field): void {
  if (obj[field] === undefined) return
  expectStringArray(obj, field, errors, label)
}

function expectOptionalOneOfArray(obj: Record<string, unknown>, field: string, allowed: string[], errors: string[], label = field): void {
  if (obj[field] === undefined) return
  if (!Array.isArray(obj[field]) || obj[field].some(value => typeof value !== 'string' || !allowed.includes(value))) {
    errors.push(`${label} must be an array containing: ${allowed.join(', ')}`)
  }
}
