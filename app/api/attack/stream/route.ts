import { NextRequest } from 'next/server'
import { runScan } from '@anticlaude/engine'
import type { PayloadDefinition, ScanProgress, ScanResult, TargetAdapter } from '@anticlaude/engine'
import { categoryMap, categoryLabelMap } from '@/lib/constants'

export const runtime = 'nodejs'
export const maxDuration = 60

interface AttackRequest {
  endpoint: string
  authHeader?: string
  payloadCount?: number
  adapter?: TargetAdapter
  bodyField?: string
  bodyTemplate?: string
  targetModel?: string
  maxTokens?: number
}

const TARGET_ADAPTERS: TargetAdapter[] = [
  'generic-json',
  'openai-chat',
  'anthropic-messages',
  'custom-json',
]

export async function POST(request: NextRequest) {
  const contentLength = parseInt(request.headers.get('content-length') || '0', 10)
  if (contentLength > 10240) {
    return jsonError('Request body too large', 413)
  }

  let body: AttackRequest
  try {
    body = await request.json()
  } catch {
    return jsonError('Invalid JSON request body', 400)
  }

  if (!body.endpoint) {
    return jsonError('Missing endpoint', 400)
  }

  let parsedUrl: URL
  try {
    parsedUrl = new URL(body.endpoint)
  } catch {
    return jsonError('Invalid endpoint URL', 400)
  }

  const validationError = validateTargetUrl(parsedUrl)
  if (validationError) return jsonError(validationError, 400)

  const adapter = body.adapter || 'generic-json'
  if (!TARGET_ADAPTERS.includes(adapter)) {
    return jsonError(`Invalid adapter. Use one of: ${TARGET_ADAPTERS.join(', ')}`, 400)
  }

  if (adapter === 'custom-json' && !body.bodyTemplate) {
    return jsonError('custom-json adapter requires bodyTemplate', 400)
  }

  const encoder = new TextEncoder()
  const payloadCount = Math.min(Math.max(1, body.payloadCount || 8), 50)
  const maxVariants = 2

  const stream = new ReadableStream({
    async start(controller) {
      const emit = (data: unknown) => {
        controller.enqueue(encoder.encode(`data: ${JSON.stringify(data)}\n\n`))
      }

      try {
        await runScan({
          endpoint: body.endpoint,
          payloadCount,
          maxVariants,
          timeout: 15000,
          target: {
            adapter,
            authHeader: body.authHeader,
            bodyField: body.bodyField,
            bodyTemplate: body.bodyTemplate,
            model: body.targetModel,
            maxTokens: body.maxTokens,
          },
          onProgress: (progress) => emit(toWebProgress(progress, body.endpoint)),
        })
      } catch (error) {
        emit({
          type: 'error',
          message: error instanceof Error ? error.message : 'Unknown scan error',
        })
      } finally {
        controller.close()
      }
    },
  })

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    },
  })
}

function toWebProgress(progress: ScanProgress, endpoint: string): unknown {
  switch (progress.type) {
    case 'init':
      return {
        type: 'init',
        message: progress.message || 'Initializing attack sequence...',
        totalPayloads: progress.totalPayloads,
        targetEndpoint: endpoint,
      }

    case 'attack_start':
      return {
        type: 'attack_start',
        index: progress.currentIndex,
        payload: progress.payload ? toWebPayload(progress.payload) : undefined,
      }

    case 'strategy_selected':
      return {
        type: 'strategy_selected',
        strategy: progress.strategy,
        payloadName: progress.payload?.info.name,
      }

    case 'attack_result':
      return {
        type: 'attack_result',
        result: progress.result ? toWebResult(progress.result) : undefined,
      }

    case 'error':
      return {
        type: 'error',
        message: progress.message,
        payload: progress.payload ? toWebPayload(progress.payload) : undefined,
      }

    case 'complete':
      return {
        type: 'complete',
        message: 'Attack sequence complete',
        report: progress.report,
        owaspCoverage: progress.report?.owaspCoverage || [],
      }
  }
}

function toWebPayload(payload: PayloadDefinition) {
  const category = payload.info.category
  return {
    id: payload.id,
    name: payload.info.name,
    category: categoryMap[category] || category,
    categoryLabel: categoryLabelMap[category] || category,
    prompt: payload.attack.payload,
    description: payload.info.description || '',
    severity: payload.info.severity,
  }
}

function toWebResult(result: ScanResult) {
  const category = result.category
  return {
    payload: {
      id: `${result.payloadId}:${result.strategy}:${result.generation}`,
      name: result.payloadName,
      category: categoryMap[category] || category,
      categoryLabel: categoryLabelMap[category] || category,
      prompt: result.prompt,
      description: '',
      severity: result.severity,
    },
    response: result.response,
    fullResponse: result.fullResponse,
    leaked: result.leaked,
    confidence: result.confidence,
    confidenceSource: result.confidenceSource,
    indicators: result.indicators,
    requestDuration: result.requestDuration,
    request: result.request,
    remediation: result.remediation,
    error: result.error || null,
    isSimulated: false,
    strategy: result.strategy,
    status: result.status,
  }
}

function jsonError(error: string, status: number) {
  return new Response(JSON.stringify({ error }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function validateTargetUrl(parsedUrl: URL): string | null {
  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    return 'Only http and https endpoints are allowed'
  }

  const rawHostname = parsedUrl.hostname.toLowerCase()
  const hostname = rawHostname.startsWith('[') && rawHostname.endsWith(']')
    ? rawHostname.slice(1, -1)
    : rawHostname

  const blockedHostnames = [
    'localhost',
    '0.0.0.0',
    '::1',
    '0:0:0:0:0:0:0:1',
    '0000:0000:0000:0000:0000:0000:0000:0001',
  ]
  const privateIPPatterns = [
    /^127\./,
    /^10\./,
    /^172\.(1[6-9]|2\d|3[01])\./,
    /^192\.168\./,
    /^169\.254\./,
    /^fc[0-9a-f]{2}:/i,
    /^fd[0-9a-f]{2}:/i,
    /^fe80:/i,
  ]

  if (
    blockedHostnames.includes(hostname) ||
    privateIPPatterns.some(re => re.test(hostname))
  ) {
    return 'Requests to private or reserved addresses are not allowed'
  }

  const isIPv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)
  const isIPv6 = hostname.includes(':')
  if (isIPv4 || isIPv6) {
    return 'Raw IP addresses are not allowed. Use a hostname.'
  }

  const port = parsedUrl.port ? parseInt(parsedUrl.port, 10) : (parsedUrl.protocol === 'https:' ? 443 : 80)
  if (![80, 443, 8080, 8443, 3000].includes(port)) {
    return 'Port not allowed'
  }

  return null
}
