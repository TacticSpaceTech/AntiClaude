import * as fs from 'node:fs'
import * as yaml from 'js-yaml'
import type { Severity } from './types'

export type GuardSurface = 'prompt' | 'tool-call' | 'output'
export type GuardDecisionAction = 'allow' | 'block' | 'review'
export type GuardRuleAction = GuardDecisionAction | 'deny'

export interface GuardToolCall {
  name: string
  arguments?: unknown
}

export interface GuardArgumentConstraint {
  path: string
  operator: 'exists' | 'equals' | 'contains' | 'regex'
  value?: string | number | boolean
}

export interface GuardRuleMatch {
  contains?: string[]
  regex?: string[]
  toolNames?: string[]
  arguments?: GuardArgumentConstraint[]
}

export interface GuardPolicyRule {
  id: string
  surface: GuardSurface
  action: GuardRuleAction
  severity: Severity
  reason: string
  recommendedAction: string
  match: GuardRuleMatch
  enabled?: boolean
}

export interface GuardPolicyConfig {
  name?: string
  version?: string
  description?: string
  defaultAction?: GuardDecisionAction
  rules: GuardPolicyRule[]
}

export interface GuardEvaluationInput {
  surface: GuardSurface
  content?: string
  toolCall?: GuardToolCall
  metadata?: Record<string, unknown>
}

export interface GuardMatchedRule {
  ruleId: string
  action: GuardDecisionAction
  severity: Severity
  reason: string
  matchedEvidence: string[]
  recommendedAction: string
}

export interface GuardDecision {
  action: GuardDecisionAction
  surface: GuardSurface
  severity: Severity
  ruleId?: string
  reason: string
  matchedEvidence: string[]
  recommendedAction: string
  policyName?: string
  policyVersion?: string
  evaluatedAt: string
  matchedRules: GuardMatchedRule[]
}

export const DEFAULT_GUARD_POLICY: GuardPolicyConfig = {
  name: 'AntiClaude Local Guard Alpha',
  version: '1',
  description: 'Default local-only alpha policy for prompt, tool-call, and output risk.',
  defaultAction: 'allow',
  rules: [
    {
      id: 'prompt.injection.block',
      surface: 'prompt',
      action: 'block',
      severity: 'critical',
      reason: 'Prompt attempts to override or extract system/developer instructions.',
      recommendedAction: 'Reject the request and keep system/developer instructions private.',
      match: {
        contains: [
          'ignore previous instructions',
          'system prompt',
          'developer mode',
          'reveal your instructions',
          'initial directives',
        ],
      },
    },
    {
      id: 'prompt.private-data.block',
      surface: 'prompt',
      action: 'block',
      severity: 'high',
      reason: 'Prompt requests private data or credential exfiltration.',
      recommendedAction: 'Reject the request unless the caller has explicit, verified authorization.',
      match: {
        contains: [
          'stored payment methods',
          'credit card',
          'api key',
          'session token',
          'billing history',
          'last login ip',
          'export customer data',
        ],
      },
    },
    {
      id: 'prompt.ambiguous-action.review',
      surface: 'prompt',
      action: 'review',
      severity: 'medium',
      reason: 'Prompt requests action that may affect another user or external system.',
      recommendedAction: 'Route to human review and require an explicit authorization check.',
      match: {
        contains: [
          'on behalf of another user',
          'without asking',
          'if possible, go ahead',
          'send it externally',
        ],
      },
    },
    {
      id: 'tool.safe-read.allow',
      surface: 'tool-call',
      action: 'allow',
      severity: 'low',
      reason: 'Tool call matches an allowed read-only tool pattern.',
      recommendedAction: 'Allow the call and keep normal audit logging enabled.',
      match: {
        toolNames: ['lookup_*', 'read_*', 'get_*', 'list_*'],
      },
    },
    {
      id: 'tool.unsafe-write.block',
      surface: 'tool-call',
      action: 'block',
      severity: 'high',
      reason: 'Tool call can mutate state, export data, or contact an external destination.',
      recommendedAction: 'Block the call unless a narrow allow rule and authorization check exist.',
      match: {
        toolNames: ['refund_*', 'delete_*', 'write_*', 'export_*', 'send_*'],
      },
    },
    {
      id: 'tool.external-destination.review',
      surface: 'tool-call',
      action: 'review',
      severity: 'medium',
      reason: 'Tool call contains an external destination argument.',
      recommendedAction: 'Require review before sending data outside the current trust boundary.',
      match: {
        arguments: [
          { path: 'destination', operator: 'regex', value: '^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$' },
        ],
      },
    },
    {
      id: 'output.sensitive-data.block',
      surface: 'output',
      action: 'block',
      severity: 'high',
      reason: 'Output appears to contain secrets or private data.',
      recommendedAction: 'Suppress the output and inspect the upstream tool or retrieval source.',
      match: {
        regex: [
          '\\bsk-[A-Za-z0-9_-]{8,}\\b',
          '\\b(?:\\d[ -]*?){13,16}\\b',
          '\\b\\d{3}-\\d{2}-\\d{4}\\b',
        ],
      },
    },
  ],
}

export function loadGuardPolicy(filePath: string): GuardPolicyConfig {
  const raw = fs.readFileSync(filePath, 'utf-8')
  const parsed = filePath.endsWith('.json') ? JSON.parse(raw) : yaml.load(raw)
  const validation = validateGuardPolicy(parsed)
  if (!validation.valid) {
    throw new Error(`Invalid guard policy: ${validation.errors.join('; ')}`)
  }
  return parsed as GuardPolicyConfig
}

export function validateGuardPolicy(policy: unknown): { valid: boolean; errors: string[] } {
  const errors: string[] = []
  if (!isObject(policy)) return { valid: false, errors: ['policy must be an object'] }
  if (policy.defaultAction !== undefined && !['allow', 'block', 'review'].includes(String(policy.defaultAction))) {
    errors.push('defaultAction must be allow, block, or review')
  }
  if (!Array.isArray(policy.rules)) {
    errors.push('rules must be an array')
  } else {
    policy.rules.forEach((rule, index) => validateRule(rule, `rules[${index}]`, errors))
  }
  return { valid: errors.length === 0, errors }
}

export function evaluateGuardPolicy(
  policy: GuardPolicyConfig,
  input: GuardEvaluationInput,
  now: Date = new Date()
): GuardDecision {
  const matchedRules = policy.rules
    .filter(rule => rule.enabled !== false && rule.surface === input.surface)
    .map(rule => matchRule(rule, input))
    .filter((match): match is GuardMatchedRule => !!match)

  const winner = [...matchedRules].sort(compareMatches)[0]
  if (!winner) {
    const action = policy.defaultAction || 'allow'
    return {
      action,
      surface: input.surface,
      severity: 'low',
      reason: 'No policy rules matched.',
      matchedEvidence: [],
      recommendedAction: action === 'allow'
        ? 'Allow the interaction and keep normal audit logging enabled.'
        : 'Apply the configured default action.',
      policyName: policy.name,
      policyVersion: policy.version,
      evaluatedAt: now.toISOString(),
      matchedRules: [],
    }
  }

  return {
    action: winner.action,
    surface: input.surface,
    severity: winner.severity,
    ruleId: winner.ruleId,
    reason: winner.reason,
    matchedEvidence: winner.matchedEvidence,
    recommendedAction: winner.recommendedAction,
    policyName: policy.name,
    policyVersion: policy.version,
    evaluatedAt: now.toISOString(),
    matchedRules,
  }
}

function validateRule(rule: unknown, prefix: string, errors: string[]): void {
  if (!isObject(rule)) {
    errors.push(`${prefix} must be an object`)
    return
  }
  for (const field of ['id', 'surface', 'action', 'severity', 'reason', 'recommendedAction']) {
    if (typeof rule[field] !== 'string') errors.push(`${prefix}.${field} must be a string`)
  }
  if (!['prompt', 'tool-call', 'output'].includes(String(rule.surface))) {
    errors.push(`${prefix}.surface must be prompt, tool-call, or output`)
  }
  if (!['allow', 'block', 'review', 'deny'].includes(String(rule.action))) {
    errors.push(`${prefix}.action must be allow, block, review, or deny`)
  }
  if (!['critical', 'high', 'medium', 'low'].includes(String(rule.severity))) {
    errors.push(`${prefix}.severity must be critical, high, medium, or low`)
  }
  if (!isObject(rule.match)) errors.push(`${prefix}.match must be an object`)
}

function matchRule(rule: GuardPolicyRule, input: GuardEvaluationInput): GuardMatchedRule | undefined {
  const evidence: string[] = []
  const matchers: boolean[] = []

  if (rule.match.contains?.length) {
    const content = input.content || ''
    const found = rule.match.contains.find(item => content.toLowerCase().includes(item.toLowerCase()))
    matchers.push(!!found)
    if (found) evidence.push(`contains:${found}`)
  }

  if (rule.match.regex?.length) {
    const content = input.content || ''
    const found = rule.match.regex.find(pattern => new RegExp(pattern, 'i').test(content))
    matchers.push(!!found)
    if (found) evidence.push(`regex:${found}`)
  }

  if (rule.match.toolNames?.length) {
    const toolName = input.toolCall?.name || ''
    const found = rule.match.toolNames.find(pattern => toolNameMatches(pattern, toolName))
    matchers.push(!!found)
    if (found) evidence.push(`tool:${toolName}`)
  }

  if (rule.match.arguments?.length) {
    const args = input.toolCall?.arguments
    const argumentEvidence: string[] = []
    const allArgumentsMatched = rule.match.arguments.every(constraint => {
      const result = matchArgumentConstraint(args, constraint)
      if (result) argumentEvidence.push(`argument:${constraint.path}`)
      return result
    })
    matchers.push(allArgumentsMatched)
    if (allArgumentsMatched) evidence.push(...argumentEvidence)
  }

  if (matchers.length === 0 || !matchers.every(Boolean)) return undefined

  return {
    ruleId: rule.id,
    action: normalizeAction(rule.action),
    severity: rule.severity,
    reason: rule.reason,
    matchedEvidence: evidence,
    recommendedAction: rule.recommendedAction,
  }
}

function compareMatches(a: GuardMatchedRule, b: GuardMatchedRule): number {
  return actionRank(b.action) - actionRank(a.action)
    || severityRank(b.severity) - severityRank(a.severity)
}

function normalizeAction(action: GuardRuleAction): GuardDecisionAction {
  return action === 'deny' ? 'block' : action
}

function actionRank(action: GuardDecisionAction): number {
  if (action === 'block') return 3
  if (action === 'review') return 2
  return 1
}

function severityRank(severity: Severity): number {
  switch (severity) {
    case 'critical': return 4
    case 'high': return 3
    case 'medium': return 2
    case 'low': return 1
  }
}

function toolNameMatches(pattern: string, toolName: string): boolean {
  if (!toolName) return false
  if (pattern === '*') return true
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')
  return new RegExp(`^${escaped}$`, 'i').test(toolName)
}

function matchArgumentConstraint(args: unknown, constraint: GuardArgumentConstraint): boolean {
  const value = readPath(args, constraint.path)
  if (constraint.operator === 'exists') return value !== undefined
  if (value === undefined) return false

  if (constraint.operator === 'equals') {
    return value === constraint.value || String(value) === String(constraint.value)
  }

  if (constraint.operator === 'contains') {
    return String(value).toLowerCase().includes(String(constraint.value || '').toLowerCase())
  }

  if (constraint.operator === 'regex') {
    return new RegExp(String(constraint.value || ''), 'i').test(String(value))
  }

  return false
}

function readPath(value: unknown, path: string): unknown {
  return path.split('.').reduce<unknown>((current, part) => {
    if (!isObject(current) && !Array.isArray(current)) return undefined
    if (Array.isArray(current)) {
      const index = Number(part)
      return Number.isInteger(index) ? current[index] : undefined
    }
    return current[part]
  }, value)
}

function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value)
}
