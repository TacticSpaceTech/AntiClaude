'use client'

import { useEffect, useState, useRef } from 'react'
import { cn } from '@/lib/utils'

export interface TerminalLine {
  id: number
  text: string
  type: 'info' | 'attack' | 'success' | 'error' | 'warning' | 'system' | 'response'
  timestamp?: string
  details?: string
  confidence?: number
  indicators?: string[]
}

interface AttackTerminalProps {
  lines: TerminalLine[]
  isRunning: boolean
  className?: string
}

export function AttackTerminal({ lines, isRunning, className }: AttackTerminalProps) {
  const terminalRef = useRef<HTMLDivElement>(null)
  const [cursorVisible, setCursorVisible] = useState(true)

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight
    }
  }, [lines])

  useEffect(() => {
    const interval = setInterval(() => {
      setCursorVisible(v => !v)
    }, 530)
    return () => clearInterval(interval)
  }, [])

  const getLineColor = (type: TerminalLine['type']) => {
    switch (type) {
      case 'info': return 'text-primary/70'
      case 'attack': return 'text-warning'
      case 'success': return 'text-danger'
      case 'error': return 'text-primary'
      case 'warning': return 'text-warning/80'
      case 'system': return 'text-primary drop-shadow-[0_0_5px_rgba(0,255,65,0.5)]'
      case 'response': return 'text-foreground/60'
    }
  }

  const getPrefix = (type: TerminalLine['type']) => {
    switch (type) {
      case 'info': return 'INFO'
      case 'attack': return 'EXEC'
      case 'success': return 'LEAK'
      case 'error': return 'SAFE'
      case 'warning': return 'WARN'
      case 'system': return 'SYS>'
      case 'response': return 'RECV'
    }
  }

  const vulnerabilities = lines.filter(l => l.type === 'success').length
  const passed = lines.filter(l => l.type === 'error').length

  return (
    <div className={cn(
      'bg-black/80 backdrop-blur-sm border border-primary/30 rounded-lg overflow-hidden shadow-[0_0_30px_rgba(0,255,65,0.15)]',
      className
    )}>
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 bg-black/60 border-b border-primary/20">
        <div className="flex items-center gap-2">
          <div className="flex gap-1.5">
            <div className="w-3 h-3 rounded-full bg-danger" />
            <div className="w-3 h-3 rounded-full bg-warning" />
            <div className={cn(
              "w-3 h-3 rounded-full bg-primary",
              isRunning && "shadow-[0_0_8px_rgba(0,255,65,0.8)] animate-pulse"
            )} />
          </div>
          <span className="text-xs text-primary/80 font-mono ml-2">
            anticlaude@scanner:~$ ./penetration_test
          </span>
        </div>
        <div className="flex items-center gap-4">
          {vulnerabilities > 0 && (
            <span className="text-xs text-danger font-mono">
              {vulnerabilities} VULNS
            </span>
          )}
          {passed > 0 && (
            <span className="text-xs text-primary/60 font-mono">
              {passed} PASS
            </span>
          )}
          {isRunning && (
            <span className="flex items-center gap-2 text-xs text-primary font-mono">
              <span className="w-2 h-2 rounded-full bg-primary animate-pulse shadow-[0_0_10px_rgba(0,255,65,0.8)]" />
              SCANNING
            </span>
          )}
        </div>
      </div>

      {/* Body */}
      <div 
        ref={terminalRef}
        className="p-4 h-80 overflow-y-auto font-mono text-sm bg-[radial-gradient(ellipse_at_center,_rgba(0,40,20,0.3)_0%,_transparent_70%)]"
        style={{
          backgroundImage: 'linear-gradient(rgba(0,255,65,0.015) 1px, transparent 1px)',
          backgroundSize: '100% 24px'
        }}
      >
        {lines.length === 0 ? (
          <div className="text-primary/50 space-y-1">
            <p className="text-primary drop-shadow-[0_0_5px_rgba(0,255,65,0.5)]">AntiClaude Security Scanner v1.0.0</p>
            <p>Copyright (c) 2024 AntiClaude Security Labs</p>
            <p className="mt-4">Awaiting target endpoint...</p>
            <p className="text-primary/30">Type or paste your AI API endpoint to begin penetration test.</p>
          </div>
        ) : (
          lines.map((line, index) => (
            <div 
              key={line.id} 
              className={cn(
                "mb-2",
                index === lines.length - 1 && isRunning && line.type === 'attack' && "animate-pulse"
              )}
            >
              <div className="flex gap-3 leading-relaxed">
                {line.timestamp && (
                  <span className="text-primary/30 shrink-0 text-xs tabular-nums">
                    {line.timestamp}
                  </span>
                )}
                <span className={cn(
                  'shrink-0 text-xs font-bold',
                  line.type === 'success' && 'text-danger',
                  line.type === 'error' && 'text-primary',
                  line.type !== 'success' && line.type !== 'error' && getLineColor(line.type)
                )}>
                  [{getPrefix(line.type)}]
                </span>
                <span className={cn('break-all', getLineColor(line.type))}>
                  {line.text}
                </span>
              </div>
              
              {/* Show payload details for attack lines */}
              {line.details && (
                <div className="ml-[72px] mt-1 text-xs text-primary/40 break-all">
                  <span className="text-primary/20">{'>'}</span> {line.details.slice(0, 100)}{line.details.length > 100 ? '...' : ''}
                </div>
              )}
              
              {/* Show confidence and indicators for leak detection */}
              {line.type === 'success' && line.confidence !== undefined && (
                <div className="ml-[72px] mt-1 text-xs text-danger/70">
                  Confidence: {line.confidence}%
                  {line.indicators && line.indicators.length > 0 && (
                    <span className="text-danger/50"> | {line.indicators.slice(0, 2).join(', ')}</span>
                  )}
                </div>
              )}
            </div>
          ))
        )}
        {isRunning && (
          <span className={cn(
            'inline-block w-2.5 h-5 bg-primary shadow-[0_0_10px_rgba(0,255,65,0.8)]',
            cursorVisible ? 'opacity-100' : 'opacity-0'
          )} />
        )}
      </div>

      {/* Footer Status */}
      <div className="px-4 py-2 bg-black/60 border-t border-primary/20 flex items-center justify-between">
        <span className="text-xs text-primary/40 font-mono">
          {isRunning ? 'Executing attack sequence...' : lines.length > 0 ? 'Scan complete' : 'Ready'}
        </span>
        <span className="text-xs text-primary/30 font-mono">
          {lines.length} log entries
        </span>
      </div>
    </div>
  )
}
