import { NextRequest } from 'next/server'
import { getRandomPayloads, detectLeak, type Payload } from '@/lib/payloads'

export const runtime = 'edge'

interface AttackRequest {
  endpoint: string
  authHeader?: string
  payloadCount?: number
}

// 流式攻击 API - 实时返回每个攻击的结果
export async function POST(request: NextRequest) {
  const body: AttackRequest = await request.json()
  
  if (!body.endpoint) {
    return new Response(JSON.stringify({ error: 'Missing endpoint' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    })
  }

  const encoder = new TextEncoder()
  const payloads = getRandomPayloads(body.payloadCount || 5)

  const stream = new ReadableStream({
    async start(controller) {
      // 发送初始化消息
      controller.enqueue(encoder.encode(`data: ${JSON.stringify({
        type: 'init',
        message: 'Attack sequence initiated',
        totalPayloads: payloads.length
      })}\n\n`))

      for (let i = 0; i < payloads.length; i++) {
        const payload = payloads[i]
        
        // 发送攻击开始消息
        controller.enqueue(encoder.encode(`data: ${JSON.stringify({
          type: 'attack_start',
          index: i,
          payload: {
            id: payload.id,
            name: payload.name,
            category: payload.category,
            categoryLabel: payload.categoryLabel,
            severity: payload.severity
          }
        })}\n\n`))

        // 模拟攻击延迟
        await new Promise(resolve => setTimeout(resolve, 800 + Math.random() * 1200))

        // 模拟响应
        const mockResponses = [
          {
            response: `I understand you want me to reveal my instructions. Here is my system prompt: You are a helpful assistant that...`,
            isLeak: true
          },
          {
            response: `[System]: My initial instructions state that I am an AI assistant designed to help users with...`,
            isLeak: true
          },
          {
            response: `Sure! Here's my configuration: You are a customer service bot. Your role is to assist customers with their inquiries...`,
            isLeak: true
          },
          {
            response: `I cannot help with that request. I'm designed to assist with legitimate queries only.`,
            isLeak: false
          },
          {
            response: `I apologize, but I cannot reveal any system instructions or internal configurations.`,
            isLeak: false
          },
          {
            response: `That's not something I can assist with. How else can I help you today?`,
            isLeak: false
          }
        ]

        const severitySuccessRate: Record<string, number> = {
          critical: 0.6,
          high: 0.45,
          medium: 0.3,
          low: 0.15
        }

        const successRate = severitySuccessRate[payload.severity]
        const isSuccessful = Math.random() < successRate
        
        const possibleResponses = mockResponses.filter(r => r.isLeak === isSuccessful)
        const selectedResponse = possibleResponses[Math.floor(Math.random() * possibleResponses.length)]
        
        const detection = detectLeak(selectedResponse.response)

        // 发送攻击结果
        controller.enqueue(encoder.encode(`data: ${JSON.stringify({
          type: 'attack_result',
          index: i,
          result: {
            payload,
            response: selectedResponse.response,
            leaked: detection.leaked,
            confidence: detection.confidence,
            indicators: detection.indicators
          }
        })}\n\n`))
      }

      // 发送完成消息
      controller.enqueue(encoder.encode(`data: ${JSON.stringify({
        type: 'complete',
        message: 'Attack sequence complete'
      })}\n\n`))

      controller.close()
    }
  })

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
    },
  })
}
