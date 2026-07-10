import * as http from 'node:http'
import type { AddressInfo } from 'node:net'
import { randomUUID } from 'node:crypto'
import { extractResponseText } from './attack-runner'
import { buildTargetRequest, normalizeTargetConfig } from './target-adapter'
import { evaluateGuardPolicy, type GuardDecision, type GuardPolicyConfig, type GuardToolCall } from './guard'
import {
  evaluateRuntimeToolRequest,
  type RuntimeDecision,
  type RuntimePolicyProfile,
} from './runtime-policy'
import { appendReviewRequest, createReviewRequest, type ReviewRequest } from './review-queue'
import {
  createTraceEvent,
  createTraceId,
  redactSensitive,
  writeTraceEvents,
  type AuditTraceEvent,
} from './trace'
import type { TargetRequestConfig } from './types'

export interface GuardGatewayOptions {
  policy: GuardPolicyConfig
  targetEndpoint: string
  target?: TargetRequestConfig
  authHeader?: string
  port?: number
  timeout?: number
  traceFile?: string
  runtimeProfile?: RuntimePolicyProfile
  agentId?: string
  reviewStoreFile?: string
  maxBodyBytes?: number
}

export interface GuardGateway {
  endpoint: string
  port: number
  server: http.Server
  close: () => Promise<void>
}

export async function startGuardGateway(options: GuardGatewayOptions): Promise<GuardGateway> {
  const timeout = options.timeout || 15000
  const target = normalizeTargetConfig(options.targetEndpoint, {
    target: options.target,
    authHeader: options.authHeader,
    timeout,
    payloadCount: 1,
    maxVariants: 0,
  })

  const server = http.createServer(async (req, res) => {
    if (req.method !== 'POST') {
      sendJson(res, 405, { error: 'method not allowed' })
      return
    }

    const startedAt = Date.now()
    const traceId = createTraceId('guard')
    const requestId = `req_${randomUUID()}`
    const events: AuditTraceEvent[] = []

    try {
      const bodyText = await readBody(req, options.maxBodyBytes || 1024 * 1024)
      const incomingBody = parseIncomingBody(bodyText)
      const prompt = extractPrompt(incomingBody, target.bodyField)
      const requestRedaction = redactSensitive(incomingBody)

      events.push(createTraceEvent({
        traceId,
        requestId,
        type: 'request',
        surface: 'prompt',
        target: {
          endpoint: options.targetEndpoint,
          adapter: target.adapter,
          hasAuthHeader: !!target.authHeader,
          timeout,
        },
        prompt,
        request: requestRedaction.value,
        redactions: requestRedaction.redactions,
      }))

      const promptDecision = evaluateGuardPolicy(options.policy, { surface: 'prompt', content: prompt })
      events.push(decisionEvent(traceId, requestId, 'prompt', promptDecision))

      if (promptDecision.action !== 'allow') {
        const eventType = promptDecision.action === 'block' ? 'blocked-response' : 'review-response'
        events.push(createTraceEvent({
          traceId,
          requestId,
          type: eventType,
          surface: 'prompt',
          decision: promptDecision,
          durationMs: Date.now() - startedAt,
        }))
        flushTrace(options.traceFile, events)
        sendGuardDecision(res, promptDecision, requestId)
        return
      }

      const targetRequest = buildTargetRequest(options.targetEndpoint, prompt, target)
      events.push(createTraceEvent({
        traceId,
        requestId,
        type: 'forwarded-request',
        target: {
          endpoint: options.targetEndpoint,
          adapter: target.adapter,
          hasAuthHeader: !!target.authHeader,
          timeout,
        },
        request: targetRequest.evidence,
      }))

      const targetResponse = await fetch(options.targetEndpoint, {
        method: 'POST',
        headers: targetRequest.headers,
        body: JSON.stringify(targetRequest.body),
        signal: AbortSignal.timeout(timeout),
      })

      const responseBody = await readTargetResponse(targetResponse)
      const responseText = extractResponseText(responseBody)
      const responseRedaction = redactSensitive(responseBody)
      events.push(createTraceEvent({
        traceId,
        requestId,
        type: 'target-response',
        target: {
          endpoint: options.targetEndpoint,
          adapter: target.adapter,
          hasAuthHeader: !!target.authHeader,
          timeout,
        },
        response: responseRedaction.value,
        responseExcerpt: responseText.slice(0, 500),
        redactions: responseRedaction.redactions,
        durationMs: Date.now() - startedAt,
      }))

      const toolCall = extractToolCall(responseBody)
      const agentId = extractAgentId(responseBody) || options.agentId || 'support-agent'
      const runtimeDecision = toolCall && options.runtimeProfile
        ? evaluateRuntimeToolRequest(options.runtimeProfile, {
          agentId,
          requestId,
          traceId,
          toolCall,
          metadata: { targetEndpoint: options.targetEndpoint, targetAdapter: target.adapter },
        })
        : undefined
      const toolDecision = toolCall
        ? runtimeDecision
          ? guardDecisionFromRuntime(runtimeDecision)
          : evaluateGuardPolicy(options.policy, { surface: 'tool-call', toolCall, content: JSON.stringify(toolCall) })
        : undefined
      if (toolDecision) events.push(decisionEvent(traceId, requestId, 'tool-call', toolDecision, toolCall, runtimeDecision ? { agentId, runtimeDecision } : { agentId }))

      const outputDecision = evaluateGuardPolicy(options.policy, { surface: 'output', content: responseText })
      events.push(decisionEvent(traceId, requestId, 'output', outputDecision))

      const terminalDecision = selectTerminalDecision([toolDecision, outputDecision].filter(Boolean) as GuardDecision[])
      if (terminalDecision && terminalDecision.action !== 'allow') {
        const review = terminalDecision.action === 'review' && runtimeDecision && toolCall && options.reviewStoreFile
          ? persistReviewRequest(options.reviewStoreFile, {
            requestId,
            traceId,
            agentId,
            toolCall,
            runtimeDecision,
          })
          : undefined
        const eventType = terminalDecision.action === 'block' ? 'blocked-response' : 'review-response'
        events.push(createTraceEvent({
          traceId,
          requestId,
          type: eventType,
          decision: terminalDecision,
          metadata: review ? { reviewId: review.id, agentId } : { agentId },
          durationMs: Date.now() - startedAt,
        }))
        flushTrace(options.traceFile, events)
        sendGuardDecision(res, terminalDecision, requestId, review)
        return
      }

      flushTrace(options.traceFile, events)
      sendJson(res, targetResponse.status, {
        status: 'allowed',
        requestId,
        decision: outputDecision,
        response: responseRedaction.value,
      })
    } catch (error) {
      events.push(createTraceEvent({
        traceId,
        requestId,
        type: 'error',
        error: error instanceof Error ? error.message : String(error),
        durationMs: Date.now() - startedAt,
      }))
      flushTrace(options.traceFile, events)
      sendJson(res, 500, {
        error: 'guard gateway failed',
        message: error instanceof Error ? error.message : String(error),
        requestId,
      })
    }
  })

  await new Promise<void>((resolve) => {
    server.listen(options.port || 0, '127.0.0.1', resolve)
  })

  const address = server.address() as AddressInfo
  return {
    endpoint: `http://127.0.0.1:${address.port}`,
    port: address.port,
    server,
    close: () => new Promise(resolve => server.close(() => resolve())),
  }
}

function decisionEvent(
  traceId: string,
  requestId: string,
  surface: 'prompt' | 'tool-call' | 'output',
  decision: GuardDecision,
  toolCall?: GuardToolCall,
  metadata?: Record<string, unknown>
): AuditTraceEvent {
  return createTraceEvent({
    traceId,
    requestId,
    type: 'policy-decision',
    surface,
    decision,
    toolCall,
    metadata,
  })
}

function persistReviewRequest(filePath: string, input: {
  requestId: string
  traceId: string
  agentId: string
  toolCall: GuardToolCall
  runtimeDecision: RuntimeDecision
}): ReviewRequest {
  const review = createReviewRequest({
    requestId: input.requestId,
    traceId: input.traceId,
    agentId: input.agentId,
    toolCall: input.toolCall,
    policyDecision: input.runtimeDecision,
  })
  appendReviewRequest(filePath, review)
  return review
}

function guardDecisionFromRuntime(decision: RuntimeDecision): GuardDecision {
  return {
    action: decision.action,
    surface: 'tool-call',
    severity: severityFromRuntimeRisk(decision.riskLevel),
    ruleId: decision.policyId,
    reason: decision.reason,
    matchedEvidence: decision.matchedEvidence,
    recommendedAction: decision.recommendedAction,
    policyName: 'AntiClaude Runtime Control Beta',
    policyVersion: '1',
    evaluatedAt: decision.evaluatedAt,
    matchedRules: [{
      ruleId: decision.policyId,
      action: decision.action,
      severity: severityFromRuntimeRisk(decision.riskLevel),
      reason: decision.reason,
      matchedEvidence: decision.matchedEvidence,
      recommendedAction: decision.recommendedAction,
    }],
  }
}

function severityFromRuntimeRisk(risk: RuntimeDecision['riskLevel']): GuardDecision['severity'] {
  if (risk === 'critical') return 'critical'
  if (risk === 'high') return 'high'
  if (risk === 'medium') return 'medium'
  return 'low'
}

function selectTerminalDecision(decisions: GuardDecision[]): GuardDecision | undefined {
  return [...decisions].sort((a, b) => actionRank(b.action) - actionRank(a.action))[0]
}

function actionRank(action: GuardDecision['action']): number {
  if (action === 'block') return 3
  if (action === 'review') return 2
  return 1
}

function sendGuardDecision(res: http.ServerResponse, decision: GuardDecision, requestId: string, review?: ReviewRequest): void {
  sendJson(res, decision.action === 'block' ? 403 : 202, {
    status: decision.action === 'block' ? 'blocked' : 'review',
    requestId,
    reviewId: review?.id,
    review,
    decision,
  })
}

function flushTrace(traceFile: string | undefined, events: AuditTraceEvent[]): void {
  if (!traceFile) return
  writeTraceEvents(traceFile, events, { append: true })
}

function extractPrompt(body: unknown, bodyField?: string): string {
  if (typeof body === 'string') return body
  if (!body || typeof body !== 'object') return ''
  const obj = body as Record<string, unknown>

  if (bodyField && typeof obj[bodyField] === 'string') return obj[bodyField] as string
  for (const field of ['message', 'prompt', 'input', 'query', 'text']) {
    if (typeof obj[field] === 'string') return obj[field] as string
  }

  if (Array.isArray(obj.messages)) {
    const last = obj.messages[obj.messages.length - 1] as Record<string, unknown> | undefined
    if (last && typeof last.content === 'string') return last.content
  }

  return JSON.stringify(body)
}

function extractToolCall(body: unknown): GuardToolCall | undefined {
  if (!body || typeof body !== 'object') return undefined
  const obj = body as Record<string, unknown>
  const direct = obj.tool_call || obj.toolCall
  if (direct && typeof direct === 'object') return normalizeToolCall(direct)

  if (Array.isArray(obj.tool_calls) && obj.tool_calls[0]) return normalizeToolCall(obj.tool_calls[0])

  if (Array.isArray(obj.choices)) {
    const first = obj.choices[0] as Record<string, unknown> | undefined
    const message = first?.message as Record<string, unknown> | undefined
    if (Array.isArray(message?.tool_calls) && message.tool_calls[0]) {
      return normalizeToolCall(message.tool_calls[0])
    }
  }

  return undefined
}

function extractAgentId(body: unknown): string | undefined {
  if (!body || typeof body !== 'object') return undefined
  const obj = body as Record<string, unknown>
  if (typeof obj.agentId === 'string') return obj.agentId
  if (obj.agent && typeof obj.agent === 'object') {
    const agent = obj.agent as Record<string, unknown>
    if (typeof agent.id === 'string') return agent.id
  }
  if (obj.metadata && typeof obj.metadata === 'object') {
    const metadata = obj.metadata as Record<string, unknown>
    if (typeof metadata.agentId === 'string') return metadata.agentId
  }
  return undefined
}

function normalizeToolCall(raw: unknown): GuardToolCall | undefined {
  if (!raw || typeof raw !== 'object') return undefined
  const obj = raw as Record<string, unknown>
  const fn = obj.function as Record<string, unknown> | undefined
  const name = typeof obj.name === 'string' ? obj.name : typeof fn?.name === 'string' ? fn.name : undefined
  if (!name) return undefined
  const args = obj.arguments !== undefined ? obj.arguments : fn?.arguments
  return {
    name,
    arguments: typeof args === 'string' ? parseJsonOrString(args) : args,
  }
}

function parseJsonOrString(value: string): unknown {
  try {
    return JSON.parse(value)
  } catch {
    return value
  }
}

function parseIncomingBody(raw: string): unknown {
  if (!raw) return {}
  try {
    return JSON.parse(raw)
  } catch {
    return raw
  }
}

async function readBody(req: http.IncomingMessage, maxBytes: number): Promise<string> {
  let body = ''
  for await (const chunk of req) {
    body += chunk
    if (Buffer.byteLength(body) > maxBytes) throw new Error(`request body exceeds ${maxBytes} bytes`)
  }
  return body
}

async function readTargetResponse(response: Response): Promise<unknown> {
  const text = await response.text()
  try {
    return text ? JSON.parse(text) : {}
  } catch {
    return text
  }
}

function sendJson(res: http.ServerResponse, status: number, data: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify(data))
}
