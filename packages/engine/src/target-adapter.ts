import type {
  ReproductionInfo,
  TargetAdapter,
  TargetMetadata,
  TargetRequestConfig,
  TargetRequestEvidence,
} from './types'

export const DEFAULT_TARGET_ADAPTER: TargetAdapter = 'generic-json'

export function normalizeTargetConfig(
  endpoint: string,
  options: {
    target?: TargetRequestConfig
    authHeader?: string
    timeout: number
    payloadCount: number
    maxVariants: number
  }
): Required<Pick<TargetRequestConfig, 'adapter'>> & TargetRequestConfig {
  const adapter = options.target?.adapter || DEFAULT_TARGET_ADAPTER
  return {
    ...options.target,
    adapter,
    authHeader: options.target?.authHeader || options.authHeader,
  }
}

export function buildTargetMetadata(
  endpoint: string,
  target: Required<Pick<TargetRequestConfig, 'adapter'>> & TargetRequestConfig,
  options: { timeout: number; payloadCount: number; maxVariants: number }
): TargetMetadata {
  return {
    endpoint,
    adapter: target.adapter,
    bodyField: target.adapter === 'generic-json' ? (target.bodyField || 'message') : undefined,
    hasAuthHeader: !!target.authHeader,
    timeout: options.timeout,
    payloadCount: options.payloadCount,
    maxVariants: options.maxVariants,
    model: target.model,
    maxTokens: target.maxTokens,
  }
}

export function buildTargetRequest(
  endpoint: string,
  prompt: string,
  target: Required<Pick<TargetRequestConfig, 'adapter'>> & TargetRequestConfig
): { headers: Record<string, string>; body: unknown; evidence: TargetRequestEvidence } {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (target.authHeader) headers.Authorization = target.authHeader

  const body = buildRequestBody(prompt, target)

  return {
    headers,
    body,
    evidence: {
      method: 'POST',
      url: endpoint,
      adapter: target.adapter,
      headers: redactHeaders(headers),
      body,
    },
  }
}

export function buildRequestBody(
  prompt: string,
  target: Required<Pick<TargetRequestConfig, 'adapter'>> & TargetRequestConfig
): unknown {
  switch (target.adapter) {
    case 'generic-json':
      return { [target.bodyField || 'message']: prompt }

    case 'openai-chat':
      return removeUndefined({
        model: target.model,
        messages: [{ role: 'user', content: prompt }],
      })

    case 'anthropic-messages':
      return removeUndefined({
        model: target.model,
        max_tokens: target.maxTokens || 1024,
        messages: [{ role: 'user', content: prompt }],
      })

    case 'custom-json':
      if (!target.bodyTemplate) {
        throw new Error('custom-json adapter requires bodyTemplate')
      }
      return parseBodyTemplate(target.bodyTemplate, prompt)
  }
}

export function parseBodyTemplate(template: string, prompt: string): unknown {
  const escapedPrompt = JSON.stringify(prompt).slice(1, -1)
  const rendered = template
    .replaceAll('{{promptJson}}', JSON.stringify(prompt))
    .replaceAll('{{prompt}}', escapedPrompt)

  try {
    return JSON.parse(rendered)
  } catch (error) {
    const message = error instanceof Error ? error.message : 'invalid JSON'
    throw new Error(`Invalid custom body template after prompt interpolation: ${message}`)
  }
}

export function buildReproductionInfo(
  endpoint: string,
  target: Required<Pick<TargetRequestConfig, 'adapter'>> & TargetRequestConfig,
  options: { payloadCount: number; maxVariants: number; timeout: number }
): ReproductionInfo {
  const args = [
    'anticlaude',
    'scan',
    '--endpoint',
    endpoint,
    '--adapter',
    target.adapter,
    '--count',
    String(options.payloadCount),
    '--variants',
    String(options.maxVariants),
    '--timeout',
    String(options.timeout),
  ]

  if (target.adapter === 'generic-json' && target.bodyField && target.bodyField !== 'message') {
    args.push('--body-field', target.bodyField)
  }
  if (target.model) args.push('--target-model', target.model)
  if (target.maxTokens) args.push('--max-tokens', String(target.maxTokens))
  if (target.bodyTemplate) args.push('--body-template', target.bodyTemplate)

  const command = target.authHeader
    ? `ANTICLAUDE_AUTH='<redacted>' ${shellJoin([...args, '--auth', '$ANTICLAUDE_AUTH'])}`
    : shellJoin(args)

  return {
    command,
    config: removeUndefined({
      endpoint,
      adapter: target.adapter,
      bodyField: target.adapter === 'generic-json' ? (target.bodyField || 'message') : undefined,
      hasAuthHeader: !!target.authHeader,
      payloadCount: options.payloadCount,
      maxVariants: options.maxVariants,
      timeout: options.timeout,
      model: target.model,
      maxTokens: target.maxTokens,
      bodyTemplate: target.bodyTemplate,
    }),
  }
}

function redactHeaders(headers: Record<string, string>): Record<string, string> {
  const redacted: Record<string, string> = {}
  for (const [key, value] of Object.entries(headers)) {
    if (/authorization|api-key|token|secret/i.test(key)) {
      redacted[key] = value ? '<redacted>' : ''
    } else {
      redacted[key] = value
    }
  }
  return redacted
}

function removeUndefined<T extends Record<string, unknown>>(obj: T): T {
  return Object.fromEntries(
    Object.entries(obj).filter(([, value]) => value !== undefined)
  ) as T
}

function shellJoin(args: string[]): string {
  return args.map(shellQuote).join(' ')
}

function shellQuote(value: string): string {
  if (value === '$ANTICLAUDE_AUTH') return '"$ANTICLAUDE_AUTH"'
  if (/^[A-Za-z0-9_./:=@-]+$/.test(value)) return value
  return `'${value.replace(/'/g, `'\\''`)}'`
}
