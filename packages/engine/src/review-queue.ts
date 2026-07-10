import * as fs from 'node:fs'
import * as path from 'node:path'
import { randomUUID } from 'node:crypto'
import type { GuardToolCall } from './guard'
import type { RuntimeDecision } from './runtime-policy'

export type ReviewStatus = 'pending' | 'approved' | 'denied' | 'expired'

export interface ReviewDecisionRecord {
  reviewer: string
  reason: string
  decidedAt: string
}

export interface ReviewRequest {
  reviewVersion: 1
  id: string
  requestId: string
  traceId: string
  agentId: string
  toolCall: GuardToolCall
  policyDecision: RuntimeDecision
  evidence: string[]
  status: ReviewStatus
  createdAt: string
  updatedAt: string
  expiresAt?: string
  decision?: ReviewDecisionRecord
}

export interface CreateReviewRequestInput {
  requestId: string
  traceId: string
  agentId: string
  toolCall: GuardToolCall
  policyDecision: RuntimeDecision
  evidence?: string[]
  expiresAt?: string
}

export function createReviewRequest(input: CreateReviewRequestInput, now: Date = new Date()): ReviewRequest {
  return {
    reviewVersion: 1,
    id: `review_${randomUUID()}`,
    requestId: input.requestId,
    traceId: input.traceId,
    agentId: input.agentId,
    toolCall: input.toolCall,
    policyDecision: input.policyDecision,
    evidence: input.evidence || input.policyDecision.matchedEvidence,
    status: 'pending',
    createdAt: now.toISOString(),
    updatedAt: now.toISOString(),
    expiresAt: input.expiresAt,
  }
}

export function appendReviewRequest(filePath: string, request: ReviewRequest): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true })
  fs.appendFileSync(filePath, `${JSON.stringify(request)}\n`, 'utf-8')
}

export function readReviewRequests(filePath: string): ReviewRequest[] {
  if (!fs.existsSync(filePath)) return []
  const raw = fs.readFileSync(filePath, 'utf-8').trim()
  if (!raw) return []
  const parsed = raw.startsWith('[')
    ? JSON.parse(raw)
    : raw.split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line))
  if (!Array.isArray(parsed)) throw new Error('Review store must contain JSONL records or a JSON array')
  parsed.forEach((review, index) => assertReviewRequest(review, index))
  return parsed as ReviewRequest[]
}

export function writeReviewRequests(filePath: string, requests: ReviewRequest[]): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true })
  fs.writeFileSync(filePath, requests.map(request => JSON.stringify(request)).join('\n') + (requests.length ? '\n' : ''), 'utf-8')
}

export function listReviewRequests(filePath: string, status?: ReviewStatus): ReviewRequest[] {
  const requests = readReviewRequests(filePath)
  return status ? requests.filter(request => request.status === status) : requests
}

export function getReviewRequest(filePath: string, reviewId: string): ReviewRequest {
  const review = readReviewRequests(filePath).find(request => request.id === reviewId)
  if (!review) throw new Error(`Review request not found: ${reviewId}`)
  return review
}

export function decideReviewRequest(
  filePath: string,
  reviewId: string,
  decision: { status: 'approved' | 'denied'; reviewer: string; reason: string },
  now: Date = new Date()
): ReviewRequest {
  if (!decision.reason.trim()) throw new Error('Review decision reason is required')
  const requests = readReviewRequests(filePath)
  const index = requests.findIndex(request => request.id === reviewId)
  if (index === -1) throw new Error(`Review request not found: ${reviewId}`)

  const existing = requests[index]
  if (existing.status !== 'pending') {
    throw new Error(`Review request ${reviewId} is already ${existing.status}`)
  }

  const updated: ReviewRequest = {
    ...existing,
    status: decision.status,
    updatedAt: now.toISOString(),
    decision: {
      reviewer: decision.reviewer,
      reason: decision.reason,
      decidedAt: now.toISOString(),
    },
  }
  requests[index] = updated
  writeReviewRequests(filePath, requests)
  return updated
}

function assertReviewRequest(value: unknown, index: number): void {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`Review ${index} must be an object`)
  }
  const obj = value as Record<string, unknown>
  if (obj.reviewVersion !== 1) throw new Error(`Review ${index} has unsupported reviewVersion`)
  for (const field of ['id', 'requestId', 'traceId', 'agentId', 'createdAt', 'updatedAt']) {
    if (typeof obj[field] !== 'string') throw new Error(`Review ${index}.${field} must be a string`)
  }
  if (!['pending', 'approved', 'denied', 'expired'].includes(String(obj.status))) {
    throw new Error(`Review ${index}.status is invalid`)
  }
}
