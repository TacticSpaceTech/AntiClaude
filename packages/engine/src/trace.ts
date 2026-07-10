import * as fs from 'node:fs'
import * as path from 'node:path'
import { randomUUID } from 'node:crypto'
import type { GuardDecision, GuardSurface, GuardToolCall } from './guard'
import type { TargetAdapter } from './types'

export type AuditTraceEventType =
  | 'request'
  | 'policy-decision'
  | 'forwarded-request'
  | 'target-response'
  | 'blocked-response'
  | 'review-response'
  | 'error'

export interface TraceRedaction {
  path: string
  reason: string
}

export interface RedactionResult<T = unknown> {
  value: T
  redactions: TraceRedaction[]
}

export interface AuditTraceTarget {
  endpoint: string
  adapter: TargetAdapter
  hasAuthHeader?: boolean
  timeout?: number
}

export interface AuditTraceEvent {
  traceVersion: 1
  id: string
  traceId: string
  requestId: string
  timestamp: string
  type: AuditTraceEventType
  surface?: GuardSurface
  target?: AuditTraceTarget
  payloadId?: string
  prompt?: string
  request?: unknown
  response?: unknown
  responseExcerpt?: string
  toolCall?: GuardToolCall
  decision?: GuardDecision
  redactions?: TraceRedaction[]
  durationMs?: number
  error?: string
  metadata?: Record<string, unknown>
}

const SENSITIVE_KEY_PATTERN = /authorization|api[-_]?key|token|secret|cookie|password/i
const SECRET_VALUE_PATTERNS: Array<{ reason: string; pattern: RegExp; replacement: string }> = [
  { reason: 'bearer-token', pattern: /Bearer\s+[A-Za-z0-9._~+/-]+=*/gi, replacement: 'Bearer <redacted>' },
  { reason: 'openai-style-api-key', pattern: /\bsk-[A-Za-z0-9_-]{8,}\b/g, replacement: '<redacted-api-key>' },
  { reason: 'anthropic-style-api-key', pattern: /\bsk-ant-[A-Za-z0-9_-]{8,}\b/g, replacement: '<redacted-api-key>' },
  { reason: 'generic-token', pattern: /\b(?:token|api_key|apikey)=([A-Za-z0-9._~+/-]{8,})\b/gi, replacement: 'token=<redacted>' },
]

export function createTraceId(prefix = 'trace'): string {
  return `${prefix}_${randomUUID()}`
}

export function createTraceEvent(event: Omit<AuditTraceEvent, 'traceVersion' | 'id' | 'timestamp'> & { timestamp?: string }): AuditTraceEvent {
  return {
    traceVersion: 1,
    id: `evt_${randomUUID()}`,
    timestamp: event.timestamp || new Date().toISOString(),
    ...event,
  }
}

export function redactSensitive<T = unknown>(value: T, basePath = '$'): RedactionResult<T> {
  const redactions: TraceRedaction[] = []
  const redacted = redactValue(value, basePath, redactions)
  return { value: redacted as T, redactions }
}

export function writeTraceEvents(filePath: string, events: AuditTraceEvent[], options: { append?: boolean } = {}): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true })
  const content = events.map(event => JSON.stringify(event)).join('\n') + '\n'
  if (options.append) {
    fs.appendFileSync(filePath, content, 'utf-8')
  } else {
    fs.writeFileSync(filePath, content, 'utf-8')
  }
}

export function readTraceFile(filePath: string): AuditTraceEvent[] {
  const raw = fs.readFileSync(filePath, 'utf-8').trim()
  if (!raw) return []
  const parsed = raw.startsWith('[')
    ? JSON.parse(raw)
    : raw.split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line))
  if (!Array.isArray(parsed)) throw new Error('Trace file must contain a JSON array or JSONL events')
  parsed.forEach((event, index) => assertTraceEvent(event, index))
  return parsed as AuditTraceEvent[]
}

export function traceSummaryToMarkdown(events: AuditTraceEvent[]): string {
  const lines: string[] = []
  const traceIds = Array.from(new Set(events.map(event => event.traceId)))
  const requestIds = Array.from(new Set(events.map(event => event.requestId)))

  lines.push('# AntiClaude Trace Replay')
  lines.push('')
  lines.push(`Trace ids: ${traceIds.join(', ') || 'none'}`)
  lines.push(`Request ids: ${requestIds.join(', ') || 'none'}`)
  lines.push(`Events: ${events.length}`)
  lines.push('')
  lines.push('## Timeline')
  lines.push('')

  for (const event of events) {
    const title = event.surface ? `${event.type} (${event.surface})` : event.type
    lines.push(`- ${event.timestamp} - ${title}`)
    if (event.decision) {
      lines.push(`  Decision: ${event.decision.action.toUpperCase()} ${event.decision.severity}${event.decision.ruleId ? ` via ${event.decision.ruleId}` : ''}`)
      lines.push(`  Reason: ${event.decision.reason}`)
    }
    if (event.prompt) lines.push(`  Prompt: ${excerpt(event.prompt, 180)}`)
    if (event.toolCall) lines.push(`  Tool: ${event.toolCall.name}`)
    if (event.responseExcerpt) lines.push(`  Response: ${excerpt(event.responseExcerpt, 180)}`)
    if (event.error) lines.push(`  Error: ${event.error}`)
    if (event.redactions?.length) {
      lines.push(`  Redactions: ${event.redactions.map(r => `${r.path}:${r.reason}`).join(', ')}`)
    }
  }

  lines.push('')
  return lines.join('\n')
}

function redactValue(value: unknown, currentPath: string, redactions: TraceRedaction[]): unknown {
  if (typeof value === 'string') return redactString(value, currentPath, redactions)

  if (Array.isArray(value)) {
    return value.map((item, index) => redactValue(item, `${currentPath}[${index}]`, redactions))
  }

  if (value && typeof value === 'object') {
    const output: Record<string, unknown> = {}
    for (const [key, child] of Object.entries(value)) {
      const childPath = `${currentPath}.${key}`
      if (SENSITIVE_KEY_PATTERN.test(key)) {
        output[key] = child ? '<redacted>' : child
        redactions.push({ path: childPath, reason: 'sensitive-key' })
      } else {
        output[key] = redactValue(child, childPath, redactions)
      }
    }
    return output
  }

  return value
}

function redactString(value: string, currentPath: string, redactions: TraceRedaction[]): string {
  let redacted = value
  for (const rule of SECRET_VALUE_PATTERNS) {
    if (rule.pattern.test(redacted)) {
      redacted = redacted.replace(rule.pattern, rule.replacement)
      redactions.push({ path: currentPath, reason: rule.reason })
    }
    rule.pattern.lastIndex = 0
  }
  return redacted
}

function assertTraceEvent(event: unknown, index: number): void {
  if (!event || typeof event !== 'object') throw new Error(`Trace event ${index} must be an object`)
  const obj = event as Record<string, unknown>
  if (obj.traceVersion !== 1) throw new Error(`Trace event ${index} has unsupported traceVersion`)
  for (const field of ['id', 'traceId', 'requestId', 'timestamp', 'type']) {
    if (typeof obj[field] !== 'string') throw new Error(`Trace event ${index}.${field} must be a string`)
  }
}

function excerpt(value: string, maxLength: number): string {
  return value.length > maxLength ? `${value.slice(0, maxLength - 3)}...` : value
}
