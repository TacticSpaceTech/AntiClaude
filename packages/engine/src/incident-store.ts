import { readTraceFile, type AuditTraceEvent } from './trace'
import type { GuardDecisionAction } from './guard'

export interface IncidentQuery {
  traceId?: string
  requestId?: string
  agentId?: string
  policyId?: string
  action?: GuardDecisionAction
  toolName?: string
}

export interface LocalIncidentRecord {
  traceId: string
  requestId: string
  firstSeenAt: string
  lastSeenAt: string
  eventCount: number
  actions: GuardDecisionAction[]
  policyIds: string[]
  toolNames: string[]
  agentIds: string[]
  reviewIds: string[]
  redactionCount: number
  events: AuditTraceEvent[]
}

export interface LocalIncidentIndex {
  indexVersion: 1
  incidents: LocalIncidentRecord[]
}

export function readIncidentStore(traceFile: string): LocalIncidentIndex {
  return buildIncidentIndex(readTraceFile(traceFile))
}

export function buildIncidentIndex(events: AuditTraceEvent[]): LocalIncidentIndex {
  const groups = new Map<string, AuditTraceEvent[]>()
  for (const event of events) {
    const key = `${event.traceId}:${event.requestId}`
    const existing = groups.get(key) || []
    existing.push(event)
    groups.set(key, existing)
  }

  const incidents = Array.from(groups.values()).map(toIncidentRecord)
  incidents.sort((a, b) => a.firstSeenAt.localeCompare(b.firstSeenAt))
  return { indexVersion: 1, incidents }
}

export function queryIncidentStore(traceFile: string, query: IncidentQuery): LocalIncidentRecord[] {
  return queryIncidentIndex(readIncidentStore(traceFile), query)
}

export function queryIncidentIndex(index: LocalIncidentIndex, query: IncidentQuery): LocalIncidentRecord[] {
  return index.incidents.filter(incident => incidentMatches(incident, query))
}

function toIncidentRecord(events: AuditTraceEvent[]): LocalIncidentRecord {
  const sorted = [...events].sort((a, b) => a.timestamp.localeCompare(b.timestamp))
  const first = sorted[0]
  const last = sorted[sorted.length - 1]
  return {
    traceId: first.traceId,
    requestId: first.requestId,
    firstSeenAt: first.timestamp,
    lastSeenAt: last.timestamp,
    eventCount: sorted.length,
    actions: unique(sorted.map(event => event.decision?.action).filter(isDefined)),
    policyIds: unique(sorted.map(event => event.decision?.ruleId).filter(isDefined)),
    toolNames: unique(sorted.map(event => event.toolCall?.name).filter(isDefined)),
    agentIds: unique(sorted.map(extractAgentId).filter(isDefined)),
    reviewIds: unique(sorted.map(extractReviewId).filter(isDefined)),
    redactionCount: sorted.reduce((total, event) => total + (event.redactions?.length || 0), 0),
    events: sorted,
  }
}

function incidentMatches(incident: LocalIncidentRecord, query: IncidentQuery): boolean {
  if (query.traceId && incident.traceId !== query.traceId) return false
  if (query.requestId && incident.requestId !== query.requestId) return false
  if (query.agentId && !incident.agentIds.includes(query.agentId)) return false
  if (query.policyId && !incident.policyIds.includes(query.policyId)) return false
  if (query.action && !incident.actions.includes(query.action)) return false
  if (query.toolName && !incident.toolNames.includes(query.toolName)) return false
  return true
}

function extractAgentId(event: AuditTraceEvent): string | undefined {
  if (typeof event.metadata?.agentId === 'string') return event.metadata.agentId
  const runtimeDecision = event.metadata?.runtimeDecision
  if (runtimeDecision && typeof runtimeDecision === 'object') {
    const obj = runtimeDecision as Record<string, unknown>
    if (typeof obj.agentId === 'string') return obj.agentId
  }
  return undefined
}

function extractReviewId(event: AuditTraceEvent): string | undefined {
  return typeof event.metadata?.reviewId === 'string' ? event.metadata.reviewId : undefined
}

function unique<T>(values: T[]): T[] {
  return Array.from(new Set(values))
}

function isDefined<T>(value: T | undefined): value is T {
  return value !== undefined
}
