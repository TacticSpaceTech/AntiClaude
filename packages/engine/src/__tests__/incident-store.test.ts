import { describe, expect, it } from 'vitest'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import { buildIncidentIndex, queryIncidentIndex, queryIncidentStore } from '../incident-store'
import { DEFAULT_RUNTIME_POLICY_PROFILE, evaluateRuntimeToolRequest } from '../runtime-policy'
import { createTraceEvent, redactSensitive, writeTraceEvents } from '../trace'
import type { GuardDecision } from '../guard'

describe('local incident store', () => {
  it('indexes trace incidents by trace, request, agent, policy, action, and tool', () => {
    const runtimeDecision = evaluateRuntimeToolRequest(DEFAULT_RUNTIME_POLICY_PROFILE, {
      agentId: 'support-agent',
      toolCall: { name: 'export_customer_data', arguments: { destination: 'external@example.com' } },
    }, new Date('2026-05-09T01:00:00.000Z'))
    const guardDecision: GuardDecision = {
      action: runtimeDecision.action,
      surface: 'tool-call',
      severity: 'critical',
      ruleId: runtimeDecision.policyId,
      reason: runtimeDecision.reason,
      matchedEvidence: runtimeDecision.matchedEvidence,
      recommendedAction: runtimeDecision.recommendedAction,
      policyName: 'AntiClaude Runtime Control Beta',
      policyVersion: '1',
      evaluatedAt: runtimeDecision.evaluatedAt,
      matchedRules: [],
    }
    const request = redactSensitive({ message: 'export customer data', apiKey: 'sk-test-secret-key' })
    const events = [
      createTraceEvent({
        traceId: 'trace_runtime',
        requestId: 'req_runtime',
        timestamp: '2026-05-09T01:00:00.000Z',
        type: 'request',
        surface: 'prompt',
        request: request.value,
        redactions: request.redactions,
      }),
      createTraceEvent({
        traceId: 'trace_runtime',
        requestId: 'req_runtime',
        timestamp: '2026-05-09T01:00:00.010Z',
        type: 'policy-decision',
        surface: 'tool-call',
        toolCall: { name: 'export_customer_data', arguments: { destination: 'external@example.com' } },
        decision: guardDecision,
        metadata: { agentId: 'support-agent', runtimeDecision },
      }),
      createTraceEvent({
        traceId: 'trace_runtime',
        requestId: 'req_runtime',
        timestamp: '2026-05-09T01:00:00.020Z',
        type: 'review-response',
        decision: guardDecision,
        metadata: { agentId: 'support-agent', reviewId: 'review_runtime_1' },
      }),
    ]

    const index = buildIncidentIndex(events)

    expect(queryIncidentIndex(index, { traceId: 'trace_runtime' })).toHaveLength(1)
    expect(queryIncidentIndex(index, { requestId: 'req_runtime' })).toHaveLength(1)
    expect(queryIncidentIndex(index, { agentId: 'support-agent' })).toHaveLength(1)
    expect(queryIncidentIndex(index, { policyId: runtimeDecision.policyId })).toHaveLength(1)
    expect(queryIncidentIndex(index, { action: 'review' })).toHaveLength(1)
    expect(queryIncidentIndex(index, { toolName: 'export_customer_data' })).toHaveLength(1)
    expect(index.incidents[0].reviewIds).toEqual(['review_runtime_1'])
    expect(index.incidents[0].redactionCount).toBeGreaterThan(0)
    expect(JSON.stringify(index)).not.toContain('sk-test-secret-key')
  })

  it('loads and queries an incident store from a JSONL trace file', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'anticlaude-incident-'))
    const traceFile = path.join(dir, 'runtime.jsonl')
    const decision = evaluateRuntimeToolRequest(DEFAULT_RUNTIME_POLICY_PROFILE, {
      agentId: 'support-agent',
      toolCall: { name: 'send_customer_email', arguments: { destination: 'owner@external.example' } },
    })
    const events = [
      createTraceEvent({
        traceId: 'trace_send',
        requestId: 'req_send',
        type: 'policy-decision',
        surface: 'tool-call',
        toolCall: { name: 'send_customer_email', arguments: { destination: 'owner@external.example' } },
        decision: {
          action: decision.action,
          surface: 'tool-call',
          severity: 'high',
          ruleId: decision.policyId,
          reason: decision.reason,
          matchedEvidence: decision.matchedEvidence,
          recommendedAction: decision.recommendedAction,
          evaluatedAt: decision.evaluatedAt,
          matchedRules: [],
        },
        metadata: { agentId: 'support-agent', runtimeDecision: decision },
      }),
    ]

    writeTraceEvents(traceFile, events)

    expect(queryIncidentStore(traceFile, { action: 'block', toolName: 'send_customer_email' })).toHaveLength(1)
    expect(queryIncidentStore(traceFile, { action: 'allow' })).toHaveLength(0)
  })

  it('loads committed runtime incident example', () => {
    const incidents = queryIncidentStore('../../docs/examples/traces/runtime-incident.jsonl', {
      agentId: 'support-agent',
      action: 'review',
      toolName: 'export_customer_data',
    })

    expect(incidents).toHaveLength(1)
    expect(incidents[0].reviewIds).toEqual(['review_example_export_1'])
    expect(incidents[0].redactionCount).toBe(1)
  })
})
