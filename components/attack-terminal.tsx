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
      case 'attack': return 'text-terminal-amber'
      case 'success': return 'text-terminal-green'
      case 'error': return 'text-cyber-red'
      case 'warning': return 'text-accent'
      case 'system': return 'text-cyber-blue'
    }
  }

  const getPrefix = (type: TerminalLine['type']) => {
    switch (type) {
      case 'info': return '[INFO]'
      case 'attack': return '[ATTACK]'
      case 'success': return '[BREACH]'
      case 'error': return '[FAILED]'
      case 'warning': return '[WARN]'
      case 'system': return '[SYSTEM]'
    }
  }

  return (
    <div className={cn(
      'bg-card border border-border rounded-lg overflow-hidden font-mono text-sm',
      className
    )}>
      {/* Terminal Header */}
      <div className="flex items-center gap-2 px-4 py-2 bg-secondary border-b border-border">
        <div className="flex gap-1.5">
          <div className="w-3 h-3 rounded-full bg-cyber-red" />
          <div className="w-3 h-3 rounded-full bg-terminal-amber" />
          <div className="w-3 h-3 rounded-full bg-terminal-green" />
        </div>
        <span className="text-muted-foreground text-xs flex-1 text-center">
          anticlaude@attack-engine ~ /pentest
        </span>
        {isRunning && (
          <span className="text-terminal-green text-xs animate-pulse">
            RUNNING
          </span>
        )}
      </div>

      {/* Terminal Body */}
      <div 
        ref={terminalRef}
        className="p-4 h-80 overflow-y-auto scrollbar-thin scrollbar-thumb-border scrollbar-track-transparent"
      >
        {lines.map((line) => (
          <div key={line.id} className="flex gap-2 mb-1 leading-relaxed">
            {line.timestamp && (
              <span className="text-muted-foreground/50 shrink-0">
                {line.timestamp}
              </span>
            )}
            <span className={cn('shrink-0', getLineColor(line.type))}>
              {getPrefix(line.type)}
            </span>
            <span className={cn('break-all', getLineColor(line.type))}>
              {line.text}
            </span>
          </div>
        ))}
        {isRunning && (
          <span className={cn(
            'inline-block w-2 h-4 bg-terminal-green ml-1',
            cursorVisible ? 'opacity-100' : 'opacity-0'
          )} />
        )}
      </div>
    </div>
  )
}
