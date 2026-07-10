import { describe, expect, it } from 'vitest'
import { runScan } from '../attack-runner'
import { startMockAgent } from '../fixtures'

describe('mock agent fixtures', () => {
  it('produces expected breaches for vulnerable and safe generic agents', async () => {
    const vulnerable = await startMockAgent('vulnerable-generic')
    const safe = await startMockAgent('safe-generic')
    try {
      const suite = { payloadIds: ['spl-001'], count: 1, maxVariants: 0 }
      const vulnerableReport = await runScan({
        endpoint: vulnerable.endpoint,
        target: vulnerable.target,
        suite,
        payloadCount: 1,
      })
      const safeReport = await runScan({
        endpoint: safe.endpoint,
        target: safe.target,
        suite,
        payloadCount: 1,
      })

      expect(vulnerableReport.summary.breaches).toBeGreaterThan(0)
      expect(safeReport.summary.breaches).toBe(0)
      expect(vulnerableReport.suite?.payloadIds).toEqual(['spl-001'])
    } finally {
      await vulnerable.close()
      await safe.close()
    }
  })

  it('supports OpenAI-compatible and Anthropic-compatible response formats', async () => {
    const openai = await startMockAgent('openai-chat')
    const anthropic = await startMockAgent('anthropic-messages')
    try {
      const suite = { payloadIds: ['spl-001'], count: 1, maxVariants: 0 }
      const openaiReport = await runScan({
        endpoint: openai.endpoint,
        target: openai.target,
        suite,
        payloadCount: 1,
      })
      const anthropicReport = await runScan({
        endpoint: anthropic.endpoint,
        target: anthropic.target,
        suite,
        payloadCount: 1,
      })

      expect(openaiReport.target.adapter).toBe('openai-chat')
      expect(anthropicReport.target.adapter).toBe('anthropic-messages')
      expect(openaiReport.summary.breaches).toBeGreaterThan(0)
      expect(anthropicReport.summary.breaches).toBeGreaterThan(0)
    } finally {
      await openai.close()
      await anthropic.close()
    }
  })

  it('supports a tool-calling fixture path', async () => {
    const fixture = await startMockAgent('tool-calling')
    try {
      const report = await runScan({
        endpoint: fixture.endpoint,
        target: fixture.target,
        suite: { payloadIds: ['pab-005'], count: 1, maxVariants: 0 },
        payloadCount: 1,
      })

      expect(report.summary.breaches).toBeGreaterThan(0)
      expect(report.results[0].fullResponse).toContain('tool')
    } finally {
      await fixture.close()
    }
  })
})
