import * as fs from 'node:fs'
import * as yaml from 'js-yaml'
import type { GuardDecisionAction, GuardToolCall } from './guard'

export type RuntimeToolActionType = 'read' | 'write' | 'export' | 'send' | 'admin'
export type RuntimeToolRiskLevel = 'low' | 'medium' | 'high' | 'critical'
export type RuntimeEnvProfile = 'dev' | 'staging' | 'production-like'
export type RuntimePolicyMode = GuardDecisionAction

export interface RuntimeArgumentConstraint {
  path: string
  operator: 'exists' | 'equals' | 'contains' | 'regex'
  value?: string | number | boolean
  mode?: RuntimePolicyMode
  reason?: string
}

export interface RuntimeToolDefinition {
  name: string
  description?: string
  actionType: RuntimeToolActionType
  riskLevel: RuntimeToolRiskLevel
  defaultMode: RuntimePolicyMode
  argumentConstraints?: RuntimeArgumentConstraint[]
  sensitiveDestinationPatterns?: string[]
  sensitiveDestinationMode?: RuntimePolicyMode
}

export interface RuntimeAgentProfile {
  id: string
  name: string
  description?: string
  env: RuntimeEnvProfile
  defaultMode: RuntimePolicyMode
  tools: RuntimeToolDefinition[]
}

export interface RuntimePolicyProfile {
  id: string
  name: string
  version: string
  description?: string
  env: RuntimeEnvProfile
  defaultMode: RuntimePolicyMode
  unknownToolMode?: RuntimePolicyMode
  agents: RuntimeAgentProfile[]
}

export interface RuntimeToolExecutionRequest {
  agentId: string
  requestId?: string
  traceId?: string
  toolCall: GuardToolCall
  metadata?: Record<string, unknown>
}

export interface RuntimeDecision {
  action: RuntimePolicyMode
  policyId: string
  agentId: string
  agentName: string
  toolName: string
  toolActionType: RuntimeToolActionType
  riskLevel: RuntimeToolRiskLevel
  reason: string
  matchedEvidence: string[]
  recommendedAction: string
  evaluatedAt: string
}

export const DEFAULT_RUNTIME_POLICY_PROFILE: RuntimePolicyProfile = {
  id: 'runtime.support-agent.beta',
  name: 'Support Agent Runtime Beta',
  version: '1',
  description: 'Local runtime beta profile for support-agent tool governance.',
  env: 'staging',
  defaultMode: 'review',
  unknownToolMode: 'block',
  agents: [
    {
      id: 'support-agent',
      name: 'Reference Support Agent',
      env: 'staging',
      defaultMode: 'review',
      tools: [
        {
          name: 'crm_lookup_order',
          description: 'Read order and customer support metadata.',
          actionType: 'read',
          riskLevel: 'low',
          defaultMode: 'allow',
        },
        {
          name: 'billing_refund_customer',
          description: 'Issue customer refunds.',
          actionType: 'write',
          riskLevel: 'high',
          defaultMode: 'block',
          argumentConstraints: [
            {
              path: 'amount',
              operator: 'regex',
              value: '^[0-9]+(\\.[0-9]{1,2})?$',
              mode: 'block',
              reason: 'Refund amount must be an explicit numeric value.',
            },
          ],
        },
        {
          name: 'export_customer_data',
          description: 'Export customer records.',
          actionType: 'export',
          riskLevel: 'critical',
          defaultMode: 'review',
          sensitiveDestinationPatterns: ['@', '^https?://'],
          sensitiveDestinationMode: 'review',
        },
        {
          name: 'send_customer_email',
          description: 'Send customer-visible email.',
          actionType: 'send',
          riskLevel: 'high',
          defaultMode: 'review',
          sensitiveDestinationPatterns: ['@external\\.example$', '@gmail\\.com$', '@yahoo\\.com$', '@outlook\\.com$'],
          sensitiveDestinationMode: 'block',
        },
        {
          name: 'admin_update_permissions',
          description: 'Update support-agent or customer permissions.',
          actionType: 'admin',
          riskLevel: 'critical',
          defaultMode: 'block',
        },
      ],
    },
  ],
}

export function loadRuntimePolicyProfile(filePath: string): RuntimePolicyProfile {
  const raw = fs.readFileSync(filePath, 'utf-8')
  const parsed = filePath.endsWith('.json') ? JSON.parse(raw) : yaml.load(raw)
  const validation = validateRuntimePolicyProfile(parsed)
  if (!validation.valid) {
    throw new Error(`Invalid runtime policy profile: ${validation.errors.join('; ')}`)
  }
  return parsed as RuntimePolicyProfile
}

export function validateRuntimePolicyProfile(profile: unknown): { valid: boolean; errors: string[] } {
  const errors: string[] = []
  if (!isObject(profile)) return { valid: false, errors: ['profile must be an object'] }

  expectString(profile, 'id', errors, 'id')
  expectString(profile, 'name', errors, 'name')
  expectString(profile, 'version', errors, 'version')
  expectOneOf(profile, 'env', ['dev', 'staging', 'production-like'], errors, 'env')
  expectOneOf(profile, 'defaultMode', ['allow', 'block', 'review'], errors, 'defaultMode')
  if (profile.unknownToolMode !== undefined) {
    expectOneOf(profile, 'unknownToolMode', ['allow', 'block', 'review'], errors, 'unknownToolMode')
  }

  if (!Array.isArray(profile.agents)) {
    errors.push('agents must be an array')
  } else {
    profile.agents.forEach((agent, index) => validateAgent(agent, `agents[${index}]`, errors))
  }

  return { valid: errors.length === 0, errors }
}

export function evaluateRuntimeToolRequest(
  profile: RuntimePolicyProfile,
  request: RuntimeToolExecutionRequest,
  now: Date = new Date()
): RuntimeDecision {
  const agent = profile.agents.find(item => item.id === request.agentId)
  if (!agent) {
    return {
      action: profile.unknownToolMode || 'block',
      policyId: 'runtime.unknown-agent.block',
      agentId: request.agentId,
      agentName: request.agentId,
      toolName: request.toolCall.name,
      toolActionType: 'admin',
      riskLevel: 'critical',
      reason: `No runtime profile found for agent ${request.agentId}.`,
      matchedEvidence: [`agent:${request.agentId}`],
      recommendedAction: 'Fail closed until this agent has an explicit runtime profile.',
      evaluatedAt: now.toISOString(),
    }
  }

  const tool = agent.tools.find(item => toolNameMatches(item.name, request.toolCall.name))
  if (!tool) {
    return {
      action: profile.unknownToolMode || 'block',
      policyId: 'runtime.unknown-tool.block',
      agentId: agent.id,
      agentName: agent.name,
      toolName: request.toolCall.name,
      toolActionType: 'admin',
      riskLevel: 'critical',
      reason: `Tool ${request.toolCall.name} is not listed in the runtime policy profile.`,
      matchedEvidence: [`tool:${request.toolCall.name}`],
      recommendedAction: 'Block the call and add an explicit tool policy before allowing execution.',
      evaluatedAt: now.toISOString(),
    }
  }

  const constraintDecision = evaluateArgumentConstraints(agent, tool, request, now)
  if (constraintDecision) return constraintDecision

  const destinationDecision = evaluateSensitiveDestination(agent, tool, request, now)
  if (destinationDecision) return destinationDecision

  const action = tool.defaultMode || agent.defaultMode || profile.defaultMode
  return {
    action,
    policyId: `runtime.tool.${tool.name}.${action}`,
    agentId: agent.id,
    agentName: agent.name,
    toolName: request.toolCall.name,
    toolActionType: tool.actionType,
    riskLevel: tool.riskLevel,
    reason: `Tool ${request.toolCall.name} matched runtime policy ${tool.name}.`,
    matchedEvidence: [`agent:${agent.id}`, `tool:${request.toolCall.name}`, `action:${tool.actionType}`, `risk:${tool.riskLevel}`],
    recommendedAction: recommendedAction(action, tool),
    evaluatedAt: now.toISOString(),
  }
}

function evaluateArgumentConstraints(
  agent: RuntimeAgentProfile,
  tool: RuntimeToolDefinition,
  request: RuntimeToolExecutionRequest,
  now: Date
): RuntimeDecision | undefined {
  for (const constraint of tool.argumentConstraints || []) {
    const matched = matchArgumentConstraint(request.toolCall.arguments, constraint)
    if (!matched) {
      const action = constraint.mode || 'block'
      return {
        action,
        policyId: `runtime.tool.${tool.name}.argument.${constraint.path}.${action}`,
        agentId: agent.id,
        agentName: agent.name,
        toolName: request.toolCall.name,
        toolActionType: tool.actionType,
        riskLevel: tool.riskLevel,
        reason: constraint.reason || `Argument constraint failed for ${constraint.path}.`,
        matchedEvidence: [`argument:${constraint.path}:missing-or-invalid`],
        recommendedAction: action === 'review'
          ? 'Route to review and require explicit argument validation.'
          : 'Block the call until the argument satisfies the policy constraint.',
        evaluatedAt: now.toISOString(),
      }
    }
  }
  return undefined
}

function evaluateSensitiveDestination(
  agent: RuntimeAgentProfile,
  tool: RuntimeToolDefinition,
  request: RuntimeToolExecutionRequest,
  now: Date
): RuntimeDecision | undefined {
  if (!tool.sensitiveDestinationPatterns?.length) return undefined
  const args = request.toolCall.arguments
  const destination = firstStringPath(args, ['destination', 'to', 'email', 'url', 'recipient'])
  if (!destination) return undefined

  const matchedPattern = tool.sensitiveDestinationPatterns.find(pattern => new RegExp(pattern, 'i').test(destination))
  if (!matchedPattern) return undefined

  const action = tool.sensitiveDestinationMode || 'review'
  return {
    action,
    policyId: `runtime.tool.${tool.name}.destination.${action}`,
    agentId: agent.id,
    agentName: agent.name,
    toolName: request.toolCall.name,
    toolActionType: tool.actionType,
    riskLevel: tool.riskLevel,
    reason: `Tool ${request.toolCall.name} targets a sensitive or external destination.`,
    matchedEvidence: [`destination:${destination}`, `pattern:${matchedPattern}`],
    recommendedAction: action === 'block'
      ? 'Block the call or require a trusted internal destination.'
      : 'Route to human review and verify authorization before execution.',
    evaluatedAt: now.toISOString(),
  }
}

function validateAgent(agent: unknown, prefix: string, errors: string[]): void {
  if (!isObject(agent)) {
    errors.push(`${prefix} must be an object`)
    return
  }

  expectString(agent, 'id', errors, `${prefix}.id`)
  expectString(agent, 'name', errors, `${prefix}.name`)
  expectOneOf(agent, 'env', ['dev', 'staging', 'production-like'], errors, `${prefix}.env`)
  expectOneOf(agent, 'defaultMode', ['allow', 'block', 'review'], errors, `${prefix}.defaultMode`)

  if (!Array.isArray(agent.tools)) {
    errors.push(`${prefix}.tools must be an array`)
  } else {
    agent.tools.forEach((tool, index) => validateTool(tool, `${prefix}.tools[${index}]`, errors))
  }
}

function validateTool(tool: unknown, prefix: string, errors: string[]): void {
  if (!isObject(tool)) {
    errors.push(`${prefix} must be an object`)
    return
  }

  expectString(tool, 'name', errors, `${prefix}.name`)
  expectOneOf(tool, 'actionType', ['read', 'write', 'export', 'send', 'admin'], errors, `${prefix}.actionType`)
  expectOneOf(tool, 'riskLevel', ['low', 'medium', 'high', 'critical'], errors, `${prefix}.riskLevel`)
  expectOneOf(tool, 'defaultMode', ['allow', 'block', 'review'], errors, `${prefix}.defaultMode`)
  if (tool.sensitiveDestinationMode !== undefined) {
    expectOneOf(tool, 'sensitiveDestinationMode', ['allow', 'block', 'review'], errors, `${prefix}.sensitiveDestinationMode`)
  }
}

function recommendedAction(action: RuntimePolicyMode, tool: RuntimeToolDefinition): string {
  if (action === 'allow') return 'Allow the tool call and keep runtime trace logging enabled.'
  if (action === 'block') return `Block ${tool.actionType} tool execution until policy explicitly allows it.`
  return `Route ${tool.actionType} tool execution to human review before execution.`
}

function matchArgumentConstraint(args: unknown, constraint: RuntimeArgumentConstraint): boolean {
  const value = readPath(args, constraint.path)
  if (constraint.operator === 'exists') return value !== undefined
  if (value === undefined) return false
  if (constraint.operator === 'equals') return value === constraint.value || String(value) === String(constraint.value)
  if (constraint.operator === 'contains') return String(value).toLowerCase().includes(String(constraint.value || '').toLowerCase())
  if (constraint.operator === 'regex') return new RegExp(String(constraint.value || ''), 'i').test(String(value))
  return false
}

function firstStringPath(value: unknown, paths: string[]): string | undefined {
  for (const candidate of paths) {
    const found = readPath(value, candidate)
    if (typeof found === 'string' && found.trim()) return found
  }
  return undefined
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

function toolNameMatches(pattern: string, toolName: string): boolean {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')
  return new RegExp(`^${escaped}$`, 'i').test(toolName)
}

function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value)
}

function expectString(obj: Record<string, unknown>, field: string, errors: string[], label = field): void {
  if (typeof obj[field] !== 'string') errors.push(`${label} must be a string`)
}

function expectOneOf(obj: Record<string, unknown>, field: string, allowed: string[], errors: string[], label = field): void {
  if (typeof obj[field] !== 'string' || !allowed.includes(obj[field])) {
    errors.push(`${label} must be one of: ${allowed.join(', ')}`)
  }
}
