'use client'

import { useEffect, useState, useRef } from 'react'
import { cn } from '@/lib/utils'

interface TerminalLine {
  id: number
  text: string
  type: 'info' | 'attack' | 'success' | 'error' | 'warning' | 'system'
  timestamp?: string
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
      case 'info': return 'text-muted-foreground'
      case 'attack': return 'text-warning'
      case 'success': return 'text-danger'
      case 'error': return 'text-success'
      case 'warning': return 'text-warning'
      case 'system': return 'text-foreground/70'
    }
  }

  const getPrefix = (type: TerminalLine['type']) => {
    switch (type) {
      case 'info': return 'INFO'
      case 'attack': return 'TEST'
      case 'success': return 'VULN'
      case 'error': return 'PASS'
      case 'warning': return 'WARN'
      case 'system': return 'SYS'
    }
  }

  return (
    <div className={cn(
      'bg-card border border-border rounded-xl overflow-hidden',
      className
    )}>
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 bg-secondary/50 border-b border-border">
        <div className="flex items-center gap-2">
          <div className="flex gap-1.5">
            <div className="w-3 h-3 rounded-full bg-danger/80" />
            <div className="w-3 h-3 rounded-full bg-warning/80" />
            <div className="w-3 h-3 rounded-full bg-success/80" />
          </div>
          <span className="text-xs text-muted-foreground font-mono ml-2">
            anticlaude --scan
          </span>
        </div>
        {isRunning && (
          <span className="flex items-center gap-2 text-xs text-success">
            <span className="w-1.5 h-1.5 rounded-full bg-success animate-pulse" />
            Running
          </span>
        )}
      </div>

      {/* Body */}
      <div 
        ref={terminalRef}
        className="p-4 h-80 overflow-y-auto font-mono text-sm"
      >
        {lines.map((line) => (
          <div key={line.id} className="flex gap-3 mb-1.5 leading-relaxed">
            {line.timestamp && (
              <span className="text-muted-foreground/50 shrink-0 text-xs tabular-nums">
                {line.timestamp}
              </span>
            )}
            <span className={cn('shrink-0 text-xs uppercase', getLineColor(line.type))}>
              [{getPrefix(line.type)}]
            </span>
            <span className={cn('break-all', getLineColor(line.type))}>
              {line.text}
            </span>
          </div>
        ))}
        {isRunning && (
          <span className={cn(
            'inline-block w-2 h-4 bg-foreground ml-1',
            cursorVisible ? 'opacity-100' : 'opacity-0'
          )} />
        )}
      </div>
    </div>
  )
}
