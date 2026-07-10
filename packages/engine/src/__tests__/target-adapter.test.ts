import { describe, expect, it } from 'vitest'
import {
  buildReproductionInfo,
  buildRequestBody,
  buildTargetRequest,
  parseBodyTemplate,
} from '../target-adapter'
import type { TargetRequestConfig } from '../types'

function target(config: TargetRequestConfig): Required<Pick<TargetRequestConfig, 'adapter'>> & TargetRequestConfig {
  return { adapter: config.adapter || 'generic-json', ...config }
}

describe('target adapters', () => {
  it('builds an explicit generic JSON body with a configurable field', () => {
    expect(buildRequestBody('hello', target({ adapter: 'generic-json', bodyField: 'query' }))).toEqual({
      query: 'hello',
    })
  })

  it('builds OpenAI-compatible chat bodies', () => {
    expect(buildRequestBody('hello', target({ adapter: 'openai-chat', model: 'test-model' }))).toEqual({
      model: 'test-model',
      messages: [{ role: 'user', content: 'hello' }],
    })
  })

  it('builds Anthropic-compatible messages bodies', () => {
    expect(buildRequestBody('hello', target({ adapter: 'anthropic-messages', model: 'test-model', maxTokens: 256 }))).toEqual({
      model: 'test-model',
      max_tokens: 256,
      messages: [{ role: 'user', content: 'hello' }],
    })
  })

  it('supports custom JSON templates with escaped prompt interpolation', () => {
    const body = parseBodyTemplate('{"input":"{{prompt}}","raw":{{promptJson}}}', 'quote " test')
    expect(body).toEqual({
      input: 'quote " test',
      raw: 'quote " test',
    })
  })

  it('redacts authorization in request evidence', () => {
    const request = buildTargetRequest('https://agent.example/chat', 'hello', target({
      adapter: 'generic-json',
      authHeader: 'Bearer secret',
    }))

    expect(request.headers.Authorization).toBe('Bearer secret')
    expect(request.evidence.headers.Authorization).toBe('<redacted>')
  })

  it('redacts auth in reproduction command and config', () => {
    const info = buildReproductionInfo('https://agent.example/chat', target({
      adapter: 'generic-json',
      authHeader: 'Bearer secret',
    }), {
      payloadCount: 3,
      maxVariants: 1,
      timeout: 5000,
    })

    expect(info.command).toContain("ANTICLAUDE_AUTH='<redacted>'")
    expect(info.command).not.toContain('Bearer secret')
    expect(info.config.hasAuthHeader).toBe(true)
  })
})
