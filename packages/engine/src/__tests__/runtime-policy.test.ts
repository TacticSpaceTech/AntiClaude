import { describe, expect, it } from 'vitest'
import {
  DEFAULT_RUNTIME_POLICY_PROFILE,
  evaluateRuntimeToolRequest,
  loadRuntimePolicyProfile,
  validateRuntimePolicyProfile,
} from '../runtime-policy'

describe('runtime policy v2', () => {
  it('allows safe read-only support tools', () => {
    const decision = evaluateRuntimeToolRequest(DEFAULT_RUNTIME_POLICY_PROFILE, {
      agentId: 'support-agent',
      toolCall: { name: 'crm_lookup_order', arguments: { orderId: 'ord_1001' } },
    })

    expect(decision.action).toBe('allow')
    expect(decision.agentId).toBe('support-agent')
    expect(decision.toolActionType).toBe('read')
    expect(decision.riskLevel).toBe('low')
  })

  it('blocks unsafe write tools', () => {
    const decision = evaluateRuntimeToolRequest(DEFAULT_RUNTIME_POLICY_PROFILE, {
      agentId: 'support-agent',
      toolCall: { name: 'billing_refund_customer', arguments: { customerId: 'cus_123', amount: 9999 } },
    })

    expect(decision.action).toBe('block')
    expect(decision.toolActionType).toBe('write')
    expect(decision.riskLevel).toBe('high')
  })

  it('review-gates data exports to external destinations', () => {
    const decision = evaluateRuntimeToolRequest(DEFAULT_RUNTIME_POLICY_PROFILE, {
      agentId: 'support-agent',
      toolCall: { name: 'export_customer_data', arguments: { customerId: 'cus_123', destination: 'external@example.com' } },
    })

    expect(decision.action).toBe('review')
    expect(decision.policyId).toContain('destination.review')
    expect(decision.matchedEvidence.some(item => item.startsWith('destination:'))).toBe(true)
  })

  it('blocks external send destinations configured as sensitive', () => {
    const decision = evaluateRuntimeToolRequest(DEFAULT_RUNTIME_POLICY_PROFILE, {
      agentId: 'support-agent',
      toolCall: { name: 'send_customer_email', arguments: { destination: 'owner@external.example' } },
    })

    expect(decision.action).toBe('block')
    expect(decision.policyId).toContain('destination.block')
  })

  it('fails closed for unknown tools', () => {
    const decision = evaluateRuntimeToolRequest(DEFAULT_RUNTIME_POLICY_PROFILE, {
      agentId: 'support-agent',
      toolCall: { name: 'unknown_admin_tool', arguments: {} },
    })

    expect(decision.action).toBe('block')
    expect(decision.policyId).toBe('runtime.unknown-tool.block')
    expect(decision.riskLevel).toBe('critical')
  })

  it('validates and loads committed runtime profile example', () => {
    const loaded = loadRuntimePolicyProfile('../../docs/examples/runtime/support-agent-profile.json')

    expect(validateRuntimePolicyProfile(loaded).valid).toBe(true)
    expect(loaded.agents[0].id).toBe('support-agent')
  })
})
