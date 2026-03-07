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
      case 'info': return 'text-primary/70'
      case 'attack': return 'text-warning'
      case 'success': return 'text-danger'
      case 'error': return 'text-primary'
      case 'warning': return 'text-warning'
      case 'system': return 'text-primary drop-shadow-[0_0_5px_rgba(0,255,65,0.5)]'
    }
  }

  const getPrefix = (type: TerminalLine['type']) => {
    switch (type) {
      case 'info': return 'INFO'
      case 'attack': return 'ATCK'
      case 'success': return 'VULN'
      case 'error': return 'PASS'
      case 'warning': return 'WARN'
      case 'system': return 'SYS>'
    }
  }

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
            <div className="w-3 h-3 rounded-full bg-primary shadow-[0_0_8px_rgba(0,255,65,0.5)]" />
          </div>
          <span className="text-xs text-primary/80 font-mono ml-2">
            anticlaude@scanner:~$ ./attack --stealth
          </span>
        </div>
        {isRunning && (
          <span className="flex items-center gap-2 text-xs text-primary font-mono">
            <span className="w-2 h-2 rounded-full bg-primary animate-pulse shadow-[0_0_10px_rgba(0,255,65,0.8)]" />
            ACTIVE
          </span>
        )}
      </div>

      {/* Body */}
      <div 
        ref={terminalRef}
        className="p-4 h-80 overflow-y-auto font-mono text-sm bg-[radial-gradient(ellipse_at_center,_rgba(0,40,20,0.3)_0%,_transparent_70%)]"
      >
        {lines.map((line, index) => (
          <div 
            key={line.id} 
            className={cn(
              "flex gap-3 mb-1.5 leading-relaxed",
              index === lines.length - 1 && isRunning && "animate-pulse"
            )}
          >
            {line.timestamp && (
              <span className="text-primary/40 shrink-0 text-xs tabular-nums">
                {line.timestamp}
              </span>
            )}
            <span className={cn('shrink-0 text-xs', getLineColor(line.type))}>
              [{getPrefix(line.type)}]
            </span>
            <span className={cn('break-all', getLineColor(line.type))}>
              {line.text}
            </span>
          </div>
        ))}
        {isRunning && (
          <span className={cn(
            'inline-block w-2.5 h-5 bg-primary ml-1 shadow-[0_0_10px_rgba(0,255,65,0.8)]',
            cursorVisible ? 'opacity-100' : 'opacity-0'
          )} />
        )}
      </div>
    </div>
  )
}
