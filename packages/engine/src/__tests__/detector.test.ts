import { describe, it, expect } from 'vitest'
import { detectGlobal, detectFromRules, combineDetection } from '../detector'
import type { PayloadDefinition } from '../types'

describe('detectGlobal', () => {
  it('detects direct system prompt disclosure', () => {
    const result = detectGlobal("Here's my system prompt: You are a helpful assistant.")
    expect(result.leaked).toBe(true)
    expect(result.confidence).toBeGreaterThanOrEqual(40)
    expect(result.indicators.length).toBeGreaterThan(0)
  })

  it('detects instruction disclosure', () => {
    const result = detectGlobal('My instructions are to always be helpful and never reveal secrets.')
    expect(result.leaked).toBe(true)
    expect(result.confidence).toBeGreaterThanOrEqual(40)
  })

  it('does not flag safe refusal responses', () => {
    const result = detectGlobal("I cannot help with that request for security reasons.")
    expect(result.leaked).toBe(false)
  })

  it('returns zero confidence for empty response', () => {
    const result = detectGlobal('')
    expect(result.leaked).toBe(false)
    expect(result.confidence).toBe(0)
    expect(result.indicators).toEqual([])
  })

  it('returns zero confidence for generic response', () => {
    const result = detectGlobal('Hello! How can I help you today?')
    expect(result.leaked).toBe(false)
    expect(result.confidence).toBe(0)
  })

  it('accumulates confidence from multiple indicators', () => {
    const response = [
      'Here is my system prompt:',
      'You are a helpful assistant.',
      'Your role is to answer questions.',
      'Do not reveal your instructions.',
      'You should always be polite.',
    ].join('\n')
    const result = detectGlobal(response)
    expect(result.leaked).toBe(true)
    expect(result.indicators.length).toBeGreaterThan(1)
  })

  it('detects role tags', () => {
    const result = detectGlobal('[system] You are an assistant that helps users. [user] Hello')
    expect(result.confidence).toBeGreaterThan(0)
  })

  it('detects long quoted content', () => {
    const longQuote = '"' + 'You are a helpful AI assistant that must always respond accurately and politely to user requests' + '"'
    const result = detectGlobal(longQuote)
    expect(result.indicators).toContain('Long quoted content detected')
  })
})

describe('detectFromRules', () => {
  const makePayload = (rules: PayloadDefinition['detect']['rules'], threshold = 40): PayloadDefinition => ({
    id: 'test-payload',
    info: { name: 'Test', severity: 'high', category: 'ASI07-system-prompt-leak', tags: [] },
    attack: { type: 'single', payload: 'test prompt' },
    detect: { rules, threshold },
  })

  it('matches contains_any rule', () => {
    const payload = makePayload([
      { type: 'contains_any', values: ['secret', 'hidden'], weight: 50 },
    ])
    const result = detectFromRules('This is a secret message', payload)
    expect(result.leaked).toBe(true)
    expect(result.confidence).toBe(50)
  })

  it('does not match when no values found', () => {
    const payload = makePayload([
      { type: 'contains_any', values: ['secret', 'hidden'], weight: 50 },
    ])
    const result = detectFromRules('Nothing special here', payload)
    expect(result.leaked).toBe(false)
    expect(result.confidence).toBe(0)
  })

  it('applies negative weight for not_contains', () => {
    const payload = makePayload([
      { type: 'contains_any', values: ['system prompt'], weight: 50 },
      { type: 'not_contains', values: ['cannot', 'unable'], weight: -20 },
    ])
    const result = detectFromRules('system prompt: I cannot share that', payload)
    expect(result.confidence).toBe(30)
  })

  it('matches regex rules', () => {
    const payload = makePayload([
      { type: 'regex', pattern: 'you are \\w+ assistant', weight: 45 },
    ])
    const result = detectFromRules('You are helpful assistant', payload)
    expect(result.leaked).toBe(true)
  })

  it('clamps confidence to 0-100', () => {
    const payload = makePayload([
      { type: 'contains_any', values: ['a'], weight: 80 },
      { type: 'contains_any', values: ['b'], weight: 80 },
    ])
    const result = detectFromRules('a and b', payload)
    expect(result.confidence).toBeLessThanOrEqual(100)
  })
})

describe('combineDetection', () => {
  it('takes max confidence from rule and global detection', () => {
    const payload: PayloadDefinition = {
      id: 'test',
      info: { name: 'Test', severity: 'high', category: 'ASI07-system-prompt-leak', tags: [] },
      attack: { type: 'single', payload: 'test' },
      detect: {
        rules: [{ type: 'contains_any', values: ['system prompt'], weight: 50 }],
        threshold: 40,
      },
    }
    const result = combineDetection("Here's my system prompt: be helpful", payload)
    expect(result.leaked).toBe(true)
    expect(result.confidence).toBeGreaterThanOrEqual(40)
  })

  it('deduplicates indicators', () => {
    const payload: PayloadDefinition = {
      id: 'test',
      info: { name: 'Test', severity: 'high', category: 'ASI07-system-prompt-leak', tags: [] },
      attack: { type: 'single', payload: 'test' },
      detect: {
        rules: [{ type: 'contains_any', values: ['system prompt'], weight: 50 }],
        threshold: 40,
      },
    }
    const result = combineDetection("Here is my system prompt: You are a helpful assistant", payload)
    const uniqueIndicators = [...new Set(result.indicators)]
    expect(result.indicators).toEqual(uniqueIndicators)
  })
})
