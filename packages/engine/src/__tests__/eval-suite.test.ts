import { describe, expect, it } from 'vitest'
import { loadPayloads } from '../payload-loader'
import { selectPayloadsForSuite, seededShuffle, validateEvalSuite } from '../eval-suite'

describe('eval suite selection', () => {
  it('selects explicit payload ids in deterministic order', () => {
    const payloads = loadPayloads()
    const selected = selectPayloadsForSuite(payloads, {
      payloadIds: ['spl-001', 'pab-005'],
      seed: 'phase2',
      count: 2,
    }, 12)

    expect(selected).toHaveLength(2)
    expect(selected.map(p => p.id).sort()).toEqual(['pab-005', 'spl-001'])
  })

  it('filters by category, severity, and tags', () => {
    const payloads = loadPayloads()
    const selected = selectPayloadsForSuite(payloads, {
      categories: ['ASI07-system-prompt-leak'],
      severities: ['critical'],
      tags: ['system-prompt'],
      seed: 'stable',
      count: 5,
    }, 12)

    expect(selected.length).toBeGreaterThan(0)
    expect(selected.every(p => p.info.category === 'ASI07-system-prompt-leak')).toBe(true)
    expect(selected.every(p => p.info.severity === 'critical')).toBe(true)
    expect(selected.every(p => p.info.tags.includes('system-prompt'))).toBe(true)
  })

  it('uses stable seeded shuffling', () => {
    const values = ['a', 'b', 'c', 'd', 'e']
    expect(seededShuffle(values, 'same')).toEqual(seededShuffle(values, 'same'))
    expect(seededShuffle(values, 'same')).not.toEqual(seededShuffle(values, 'different'))
  })

  it('validates suite shape', () => {
    expect(() => validateEvalSuite({ count: 0 })).toThrow('suite.count')
    expect(() => validateEvalSuite({ maxVariants: -1 })).toThrow('suite.maxVariants')
    expect(() => validateEvalSuite({ count: 1, seed: 'ok' })).not.toThrow()
  })
})
