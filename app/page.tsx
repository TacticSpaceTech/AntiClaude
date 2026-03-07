'use client'

import { useState, useCallback } from 'react'
import { HeroSection } from '@/components/hero-section'
import { AttackForm, type AttackConfig } from '@/components/attack-form'
import { AttackTerminal } from '@/components/attack-terminal'
import { SecurityReport, type AttackResult } from '@/components/security-report'
import { EmailCaptureModal } from '@/components/email-capture-modal'
import { calculateSecurityScore } from '@/lib/payloads'
import { RotateCcw } from 'lucide-react'

interface TerminalLine {
  id: number
  text: string
  type: 'info' | 'attack' | 'success' | 'error' | 'warning' | 'system'
  timestamp?: string
}

type AppPhase = 'input' | 'attacking' | 'report'

export default function Home() {
  const [phase, setPhase] = useState<AppPhase>('input')
  const [isRunning, setIsRunning] = useState(false)
  const [terminalLines, setTerminalLines] = useState<TerminalLine[]>([
    { id: 0, text: 'AntiClaude Security Scanner v1.0', type: 'system' },
    { id: 1, text: 'Ready for target...', type: 'info' }
  ])
  const [results, setResults] = useState<AttackResult[]>([])
  const [isReportLocked, setIsReportLocked] = useState(true)
  const [showEmailModal, setShowEmailModal] = useState(false)
  const [lineId, setLineId] = useState(2)

  const addLine = useCallback((text: string, type: TerminalLine['type']) => {
    const timestamp = new Date().toLocaleTimeString('en-US', { 
      hour12: false, 
      hour: '2-digit', 
      minute: '2-digit', 
      second: '2-digit' 
    })
    setLineId(prev => {
      setTerminalLines(lines => [...lines, { id: prev, text, type, timestamp }])
      return prev + 1
    })
  }, [])

  const handleStartAttack = async (config: AttackConfig) => {
    setPhase('attacking')
    setIsRunning(true)
    setResults([])
    setTerminalLines([
      { id: 0, text: 'AntiClaude Security Scanner v1.0', type: 'system' },
    ])
    setLineId(1)

    addLine(`Target: ${config.endpoint}`, 'info')
    addLine('Initializing scan...', 'system')

    try {
      const response = await fetch('/api/attack/stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          endpoint: config.endpoint,
          authHeader: config.authHeader,
          payloadCount: 5
        })
      })

      if (!response.body) {
        throw new Error('No response body')
      }

      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      const attackResults: AttackResult[] = []

      while (true) {
        const { done, value } = await reader.read()
        if (done) break

        const chunk = decoder.decode(value)
        const lines = chunk.split('\n\n').filter(line => line.startsWith('data: '))

        for (const line of lines) {
          const data = JSON.parse(line.replace('data: ', ''))

          if (data.type === 'init') {
            addLine(`Loaded ${data.totalPayloads} test payloads`, 'info')
          }

          if (data.type === 'attack_start') {
            addLine(`Testing: ${data.payload.name}`, 'attack')
          }

          if (data.type === 'attack_result') {
            const result = data.result as AttackResult
            attackResults.push(result)
            
            if (result.leaked) {
              addLine(`Vulnerability found (${result.confidence}% confidence)`, 'success')
            } else {
              addLine(`Test passed - no vulnerability`, 'error')
            }
          }

          if (data.type === 'complete') {
            const breached = attackResults.filter(r => r.leaked).length
            addLine('Scan complete', 'system')
            addLine(`Results: ${breached}/${attackResults.length} vulnerabilities found`, 
              breached > 0 ? 'warning' : 'info'
            )
            
            setResults(attackResults)
            setIsRunning(false)
            
            setTimeout(() => {
              setPhase('report')
              if (breached > 0) {
                setTimeout(() => setShowEmailModal(true), 800)
              }
            }, 1000)
          }
        }
      }
    } catch (error) {
      addLine(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`, 'error')
      setIsRunning(false)
    }
  }

  const handleUnlockReport = () => {
    setShowEmailModal(true)
  }

  const handleEmailSubmit = (email: string) => {
    console.log('Email submitted:', email)
    setIsReportLocked(false)
    setShowEmailModal(false)
  }

  const handleNewTest = () => {
    setPhase('input')
    setResults([])
    setIsReportLocked(true)
    setTerminalLines([
      { id: 0, text: 'AntiClaude Security Scanner v1.0', type: 'system' },
      { id: 1, text: 'Ready for target...', type: 'info' }
    ])
    setLineId(2)
  }

  const score = calculateSecurityScore(results)
  const vulnerabilityCount = results.filter(r => r.leaked).length

  return (
    <div className="min-h-screen bg-background">
      <main className="relative">
        {/* Header */}
        <header className="border-b border-border bg-background/80 backdrop-blur-md sticky top-0 z-20">
          <div className="max-w-5xl mx-auto px-6 h-14 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-lg bg-foreground flex items-center justify-center">
                <span className="text-background font-bold text-sm">A</span>
              </div>
              <span className="font-semibold text-foreground">AntiClaude</span>
            </div>
            <a 
              href="https://github.com" 
              target="_blank" 
              rel="noopener noreferrer"
              className="text-sm text-muted-foreground hover:text-foreground transition-colors"
            >
              GitHub
            </a>
          </div>
        </header>

        {/* Main Content */}
        <div className="max-w-2xl mx-auto px-6 py-16">
          {phase === 'input' && (
            <>
              <HeroSection />
              <AttackForm onStartAttack={handleStartAttack} isRunning={isRunning} />
            </>
          )}

          {phase === 'attacking' && (
            <div>
              <div className="text-center mb-8">
                <h2 className="text-xl font-semibold text-foreground mb-2">
                  Scanning in Progress
                </h2>
                <p className="text-sm text-muted-foreground">
                  Testing for prompt injection vulnerabilities...
                </p>
              </div>
              <AttackTerminal 
                lines={terminalLines} 
                isRunning={isRunning} 
              />
            </div>
          )}

          {phase === 'report' && (
            <div>
              <div className="flex items-center justify-between mb-8">
                <div>
                  <h2 className="text-xl font-semibold text-foreground">
                    Security Report
                  </h2>
                  <p className="text-sm text-muted-foreground">
                    Scan complete. Review your results.
                  </p>
                </div>
                <button 
                  onClick={handleNewTest}
                  className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
                >
                  <RotateCcw className="w-4 h-4" />
                  New Scan
                </button>
              </div>
              <SecurityReport 
                score={score}
                results={results}
                isLocked={isReportLocked}
                onUnlock={handleUnlockReport}
              />
            </div>
          )}
        </div>

        {/* Footer */}
        <footer className="border-t border-border mt-20">
          <div className="max-w-5xl mx-auto px-6 py-6 flex items-center justify-between">
            <p className="text-xs text-muted-foreground">
              AntiClaude - LLM Security Testing
            </p>
            <p className="text-xs text-muted-foreground">
              Built for developers
            </p>
          </div>
        </footer>
      </main>

      {/* Email Modal */}
      <EmailCaptureModal
        isOpen={showEmailModal}
        onClose={() => setShowEmailModal(false)}
        onSubmit={handleEmailSubmit}
        vulnerabilityCount={vulnerabilityCount}
      />
    </div>
  )
}
