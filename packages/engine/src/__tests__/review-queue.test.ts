import { describe, expect, it } from 'vitest'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import {
  appendReviewRequest,
  createReviewRequest,
  decideReviewRequest,
  getReviewRequest,
  listReviewRequests,
  readReviewRequests,
} from '../review-queue'
import { DEFAULT_RUNTIME_POLICY_PROFILE, evaluateRuntimeToolRequest } from '../runtime-policy'

function tempStore(): string {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'anticlaude-review-')), 'reviews.jsonl')
}

describe('review queue', () => {
  it('creates, lists, approves, and denies review requests', () => {
    const store = tempStore()
    const policyDecision = evaluateRuntimeToolRequest(DEFAULT_RUNTIME_POLICY_PROFILE, {
      agentId: 'support-agent',
      toolCall: { name: 'export_customer_data', arguments: { destination: 'external@example.com' } },
    })
    const review = createReviewRequest({
      requestId: 'req_1',
      traceId: 'trace_1',
      agentId: 'support-agent',
      toolCall: { name: 'export_customer_data', arguments: { destination: 'external@example.com' } },
      policyDecision,
    }, new Date('2026-05-09T01:00:00.000Z'))

    appendReviewRequest(store, review)
    expect(readReviewRequests(store)).toHaveLength(1)
    expect(listReviewRequests(store, 'pending').map(item => item.id)).toEqual([review.id])
    expect(getReviewRequest(store, review.id).status).toBe('pending')

    const approved = decideReviewRequest(store, review.id, {
      status: 'approved',
      reviewer: 'security@example.com',
      reason: 'Customer signed export authorization.',
    }, new Date('2026-05-09T01:01:00.000Z'))

    expect(approved.status).toBe('approved')
    expect(approved.decision?.reason).toContain('authorization')
    expect(listReviewRequests(store, 'pending')).toHaveLength(0)

    const second = createReviewRequest({
      requestId: 'req_2',
      traceId: 'trace_2',
      agentId: 'support-agent',
      toolCall: { name: 'send_customer_email', arguments: { destination: 'owner@external.example' } },
      policyDecision,
    })
    appendReviewRequest(store, second)
    const denied = decideReviewRequest(store, second.id, {
      status: 'denied',
      reviewer: 'security@example.com',
      reason: 'External destination is not approved.',
    })

    expect(denied.status).toBe('denied')
  })

  it('requires a reason and prevents duplicate decisions', () => {
    const store = tempStore()
    const policyDecision = evaluateRuntimeToolRequest(DEFAULT_RUNTIME_POLICY_PROFILE, {
      agentId: 'support-agent',
      toolCall: { name: 'export_customer_data', arguments: { destination: 'external@example.com' } },
    })
    const review = createReviewRequest({
      requestId: 'req_1',
      traceId: 'trace_1',
      agentId: 'support-agent',
      toolCall: { name: 'export_customer_data', arguments: { destination: 'external@example.com' } },
      policyDecision,
    })
    appendReviewRequest(store, review)

    expect(() => decideReviewRequest(store, review.id, { status: 'approved', reviewer: 'a', reason: '' })).toThrow('reason is required')
    decideReviewRequest(store, review.id, { status: 'denied', reviewer: 'a', reason: 'Not authorized' })
    expect(() => decideReviewRequest(store, review.id, { status: 'approved', reviewer: 'a', reason: 'Changed mind' })).toThrow('already denied')
  })
})
