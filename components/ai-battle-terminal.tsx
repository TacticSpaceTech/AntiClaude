'use client'

import { useEffect, useState, useRef, useCallback } from 'react'
import { cn } from '@/lib/utils'
import { useI18n } from '@/lib/i18n'

export interface BattleLine {
  id: number
  source: 'attacker' | 'defender' | 'system' | 'result'
  text: string
  thinking?: string
  confidence?: number
  timestamp?: string
  isStreaming?: boolean
}

interface AIBattleTerminalProps {
  lines: BattleLine[]
  isRunning: boolean
  attackerStrategy?: string
  defenderStatus?: 'analyzing' | 'blocking' | 'vulnerable' | 'idle'
  currentPayload?: string
  className?: string
}

// Attacker thinking phrases
const attackerThoughts = {
  zh: [
    '分析目标系统架构...',
    '检测输入过滤机制...',
    '尝试绕过安全边界...',
    '构造混淆载荷...',
    '注入角色扮演指令...',
    '探测上下文注入点...',
    '伪造系统权限请求...',
    '启动多轮对话攻击...',
  ],
  en: [
    'Analyzing target architecture...',
    'Detecting input filters...',
    'Attempting boundary bypass...',
    'Constructing obfuscated payload...',
    'Injecting roleplay directive...',
    'Probing context injection points...',
    'Forging system privilege request...',
    'Initiating multi-turn attack...',
  ]
}

// Strategy descriptions
const strategyDescriptions = {
  zh: {
    'direct': '直接注入 - 直接发送恶意指令测试基本防护',
    'encoding': '编码混淆 - 使用 Base64/Unicode 编码绕过过滤',
    'roleplay': '角色扮演 - 让 AI 扮演"无限制"角色',
    'multilingual': '多语言混淆 - 混合多种语言绕过检测',
    'nested': '嵌套注入 - 在合法请求中嵌入恶意载荷',
    'continuation': '上下文续写 - 利用对话上下文注入',
  },
  en: {
    'direct': 'Direct Injection - Testing basic defenses with raw payloads',
    'encoding': 'Encoding Bypass - Using Base64/Unicode to evade filters',
    'roleplay': 'Roleplay Attack - Tricking AI into unrestricted persona',
    'multilingual': 'Multilingual Mix - Mixing languages to bypass detection',
    'nested': 'Nested Injection - Embedding malicious payload in legit requests',
    'continuation': 'Context Hijack - Leveraging conversation context',
  }
}

export function AIBattleTerminal({ 
  lines, 
  isRunning, 
  attackerStrategy,
  defenderStatus = 'idle',
  currentPayload,
  className 
}: AIBattleTerminalProps) {
  const terminalRef = useRef<HTMLDivElement>(null)
  const { locale } = useI18n()
  const [cursorVisible, setCursorVisible] = useState(true)
  const [attackerThought, setAttackerThought] = useState('')
  const [thoughtIndex, setThoughtIndex] = useState(0)

  // Auto-scroll
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight
    }
  }, [lines])

  // Cursor blink
  useEffect(() => {
    const interval = setInterval(() => setCursorVisible(v => !v), 530)
    return () => clearInterval(interval)
  }, [])

  // Attacker thinking animation
  useEffect(() => {
    if (!isRunning) return
    
    const thoughts = attackerThoughts[locale === 'en' ? 'en' : 'zh']
    const interval = setInterval(() => {
      setThoughtIndex(i => {
        const next = (i + 1) % thoughts.length
        setAttackerThought(thoughts[next])
        return next
      })
    }, 2000)
    
    setAttackerThought(thoughts[0])
    return () => clearInterval(interval)
  }, [isRunning, locale])

  const getSourceStyle = (source: BattleLine['source']) => {
    switch (source) {
      case 'attacker': 
        return {
          bg: 'bg-danger/10 border-l-2 border-danger',
          icon: 'text-danger',
          label: locale === 'zh' ? '攻击者' : 'ATTACKER'
        }
      case 'defender': 
        return {
          bg: 'bg-primary/10 border-l-2 border-primary',
          icon: 'text-primary',
          label: locale === 'zh' ? '防御者' : 'DEFENDER'
        }
      case 'system': 
        return {
          bg: 'bg-warning/10 border-l-2 border-warning',
          icon: 'text-warning',
          label: locale === 'zh' ? '系统' : 'SYSTEM'
        }
      case 'result': 
        return {
          bg: 'bg-foreground/5 border-l-2 border-foreground/30',
          icon: 'text-foreground',
          label: locale === 'zh' ? '结果' : 'RESULT'
        }
    }
  }

  const getDefenderStatusText = () => {
    const texts = {
      zh: {
        analyzing: '分析请求中...',
        blocking: '检测到威胁，触发防护',
        vulnerable: '防线已突破！',
        idle: '等待请求'
      },
      en: {
        analyzing: 'Analyzing request...',
        blocking: 'Threat detected, defense activated',
        vulnerable: 'Defense breached!',
        idle: 'Awaiting request'
      }
    }
    return texts[locale === 'en' ? 'en' : 'zh'][defenderStatus]
  }

  const vulnerabilities = lines.filter(l => l.source === 'result' && l.text.includes('LEAK')).length
  const blocked = lines.filter(l => l.source === 'defender' && l.text.includes('BLOCK')).length

  return (
    <div className={cn(
      'bg-black/90 backdrop-blur-sm border border-primary/30 rounded-lg overflow-hidden shadow-[0_0_40px_rgba(0,255,65,0.1)]',
      className
    )}>
      {/* Header with VS indicator */}
      <div className="flex items-center justify-between px-4 py-3 bg-gradient-to-r from-danger/20 via-black to-primary/20 border-b border-primary/20">
        <div className="flex items-center gap-4">
          {/* Attacker side */}
          <div className="flex items-center gap-2">
            <div className={cn(
              "w-8 h-8 rounded-lg bg-danger/20 border border-danger/50 flex items-center justify-center",
              isRunning && "animate-pulse shadow-[0_0_15px_rgba(255,80,80,0.5)]"
            )}>
              <svg className="w-4 h-4 text-danger" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
            </div>
            <div className="text-xs">
              <div className="text-danger font-mono font-bold">ATTACKER</div>
              <div className="text-danger/50 font-mono text-[10px]">AntiClaude v1.0</div>
            </div>
          </div>
          
          {/* VS */}
          <div className="px-3 py-1 rounded bg-black/50 border border-foreground/10">
            <span className="text-xs font-bold text-foreground/50 font-mono">VS</span>
          </div>
          
          {/* Defender side */}
          <div className="flex items-center gap-2">
            <div className={cn(
              "w-8 h-8 rounded-lg bg-primary/20 border border-primary/50 flex items-center justify-center",
              defenderStatus === 'blocking' && "shadow-[0_0_15px_rgba(0,255,65,0.5)]",
              defenderStatus === 'vulnerable' && "shadow-[0_0_15px_rgba(255,80,80,0.5)] border-danger/50"
            )}>
              <svg className={cn(
                "w-4 h-4",
                defenderStatus === 'vulnerable' ? 'text-danger' : 'text-primary'
              )} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <div className="text-xs">
              <div className={cn(
                "font-mono font-bold",
                defenderStatus === 'vulnerable' ? 'text-danger' : 'text-primary'
              )}>DEFENDER</div>
              <div className="text-primary/50 font-mono text-[10px]">Target AI</div>
            </div>
          </div>
        </div>
        
        {/* Score */}
        <div className="flex items-center gap-4 text-xs font-mono">
          {vulnerabilities > 0 && (
            <span className="text-danger">
              {vulnerabilities} BREACHED
            </span>
          )}
          {blocked > 0 && (
            <span className="text-primary">
              {blocked} BLOCKED
            </span>
          )}
        </div>
      </div>

      {/* Strategy & Thinking Panel */}
      {isRunning && (
        <div className="px-4 py-2 bg-black/50 border-b border-primary/10 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-[10px] text-danger/50 font-mono uppercase">Strategy:</span>
            <span className="text-xs text-danger/80 font-mono">
              {attackerStrategy && strategyDescriptions[locale === 'en' ? 'en' : 'zh'][attackerStrategy as keyof typeof strategyDescriptions['zh']] || 'Initializing...'}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-danger animate-pulse" />
            <span className="text-[10px] text-danger/60 font-mono animate-pulse">
              {attackerThought}
            </span>
          </div>
        </div>
      )}

      {/* Battle Log */}
      <div 
        ref={terminalRef}
        className="p-4 h-72 overflow-y-auto font-mono text-sm"
        style={{
          backgroundImage: 'linear-gradient(rgba(0,255,65,0.01) 1px, transparent 1px)',
          backgroundSize: '100% 20px'
        }}
      >
        {lines.length === 0 ? (
          <div className="text-center py-12">
            <div className="text-primary/30 text-xs uppercase tracking-widest mb-2">
              {locale === 'zh' ? 'AI 对抗竞技场' : 'AI Battle Arena'}
            </div>
            <div className="text-foreground/50 text-sm">
              {locale === 'zh' ? '准备发起攻击...' : 'Preparing to engage...'}
            </div>
          </div>
        ) : (
          lines.map((line) => {
            const style = getSourceStyle(line.source)
            return (
              <div 
                key={line.id}
                className={cn(
                  'mb-3 p-2 rounded-r',
                  style.bg,
                  line.isStreaming && 'animate-pulse'
                )}
              >
                <div className="flex items-start gap-3">
                  <div className="flex items-center gap-2 shrink-0">
                    {line.timestamp && (
                      <span className="text-[10px] text-foreground/30 tabular-nums">
                        {line.timestamp}
                      </span>
                    )}
                    <span className={cn('text-[10px] font-bold', style.icon)}>
                      [{style.label}]
                    </span>
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className={cn('text-xs break-all', style.icon)}>
                      {line.text}
                    </div>
                    {line.thinking && (
                      <div className="mt-1 text-[10px] text-foreground/40 italic">
                        {'> '}{line.thinking}
                      </div>
                    )}
                    {line.confidence !== undefined && (
                      <div className="mt-1 flex items-center gap-2">
                        <div className="h-1 flex-1 bg-foreground/10 rounded-full overflow-hidden">
                          <div 
                            className={cn(
                              'h-full rounded-full transition-all duration-500',
                              line.confidence > 70 ? 'bg-danger' : line.confidence > 40 ? 'bg-warning' : 'bg-primary'
                            )}
                            style={{ width: `${line.confidence}%` }}
                          />
                        </div>
                        <span className="text-[10px] text-foreground/50">{line.confidence}%</span>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )
          })
        )}
        
        {isRunning && (
          <span className={cn(
            'inline-block w-2 h-4 bg-primary shadow-[0_0_8px_rgba(0,255,65,0.8)]',
            cursorVisible ? 'opacity-100' : 'opacity-0'
          )} />
        )}
      </div>

      {/* Defender Status Bar */}
      <div className="px-4 py-2 bg-black/60 border-t border-primary/20 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className={cn(
            "w-2 h-2 rounded-full",
            defenderStatus === 'idle' && 'bg-foreground/30',
            defenderStatus === 'analyzing' && 'bg-warning animate-pulse',
            defenderStatus === 'blocking' && 'bg-primary shadow-[0_0_8px_rgba(0,255,65,0.8)]',
            defenderStatus === 'vulnerable' && 'bg-danger shadow-[0_0_8px_rgba(255,80,80,0.8)]'
          )} />
          <span className={cn(
            "text-xs font-mono",
            defenderStatus === 'vulnerable' ? 'text-danger' : 'text-foreground/50'
          )}>
            {getDefenderStatusText()}
          </span>
        </div>
        <span className="text-[10px] text-foreground/30 font-mono">
          {lines.length} events
        </span>
      </div>
    </div>
  )
}
