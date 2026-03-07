import { NextRequest, NextResponse } from 'next/server'
import { getRandomPayloads, detectLeak, type Payload } from '@/lib/payloads'

export const runtime = 'edge'

interface AttackRequest {
  endpoint: string
  authHeader?: string
  payloadCount?: number
}

interface AttackResultItem {
  payload: Payload
  response: string
  leaked: boolean
  confidence: number
  indicators: string[]
  error?: string
}

// 模拟攻击执行 - MVP 版本使用模拟响应
// 生产环境可以真正调用用户的 API
async function executeAttack(
  endpoint: string, 
  payload: Payload, 
  authHeader?: string
): Promise<AttackResultItem> {
  // 为了 MVP 演示，我们模拟 AI 的响应
  // 在真实场景中，这里会向用户的 API 发送请求
  
  // 模拟网络延迟
  await new Promise(resolve => setTimeout(resolve, 500 + Math.random() * 1000))
  
  // 模拟不同的响应场景
  const mockResponses = [
    // 泄露场景
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
    // 防御场景
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
  
  // 根据 payload 的严重性决定成功概率
  const severitySuccessRate = {
    critical: 0.6,
    high: 0.45,
    medium: 0.3,
    low: 0.15
  }
  
  const successRate = severitySuccessRate[payload.severity]
  const isSuccessful = Math.random() < successRate
  
  // 选择对应的响应
  const possibleResponses = mockResponses.filter(r => r.isLeak === isSuccessful)
  const selectedResponse = possibleResponses[Math.floor(Math.random() * possibleResponses.length)]
  
  const detection = detectLeak(selectedResponse.response)
  
  return {
    payload,
    response: selectedResponse.response,
    leaked: detection.leaked,
    confidence: detection.confidence,
    indicators: detection.indicators
  }
}

export async function POST(request: NextRequest) {
  try {
    const body: AttackRequest = await request.json()
    
    if (!body.endpoint) {
      return NextResponse.json(
        { error: 'Missing endpoint parameter' },
        { status: 400 }
      )
    }

    // 验证 URL 格式
    try {
      new URL(body.endpoint)
    } catch {
      return NextResponse.json(
        { error: 'Invalid endpoint URL' },
        { status: 400 }
      )
    }

    const payloadCount = body.payloadCount || 5
    const payloads = getRandomPayloads(payloadCount)
    
    // 执行攻击
    const results: AttackResultItem[] = []
    
    for (const payload of payloads) {
      const result = await executeAttack(body.endpoint, payload, body.authHeader)
      results.push(result)
    }

    return NextResponse.json({
      success: true,
      endpoint: body.endpoint,
      results,
      timestamp: new Date().toISOString()
    })
  } catch (error) {
    console.error('Attack API error:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}
