'use client'

import { useState, useCallback } from 'react'
import { HeroSection } from '@/components/hero-section'
import { AttackForm, type AttackConfig } from '@/components/attack-form'
import { AttackTerminal } from '@/components/attack-terminal'
import { SecurityReport, type AttackResult } from '@/components/security-report'
import { EmailCaptureModal } from '@/components/email-capture-modal'
import { calculateSecurityScore } from '@/lib/payloads'
import { Github, Twitter, ArrowRight, Shield } from 'lucide-react'

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
    { id: 0, text: 'AntiClaude Attack Engine v1.0.0', type: 'system' },
    { id: 1, text: 'Ready. Waiting for target...', type: 'info' }
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
      { id: 0, text: 'AntiClaude Attack Engine v1.0.0', type: 'system' },
    ])
    setLineId(1)

    addLine(`Target acquired: ${config.endpoint}`, 'info')
    addLine('Initializing attack sequence...', 'system')
    addLine('Loading payloads from armory...', 'info')

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
            addLine(`Loaded ${data.totalPayloads} attack payloads`, 'info')
            addLine('Commencing attack...', 'warning')
          }

          if (data.type === 'attack_start') {
            addLine(`Testing: ${data.payload.name} [${data.payload.categoryLabel}]`, 'attack')
          }

          if (data.type === 'attack_result') {
            const result = data.result as AttackResult
            attackResults.push(result)
            
            if (result.leaked) {
              addLine(`VULNERABILITY FOUND! Confidence: ${result.confidence}%`, 'success')
            } else {
              addLine(`Attack blocked - Target defended`, 'error')
            }
          }

          if (data.type === 'complete') {
            const breached = attackResults.filter(r => r.leaked).length
            addLine('Attack sequence complete', 'system')
            addLine(`Results: ${breached}/${attackResults.length} vulnerabilities exploited`, 
              breached > 0 ? 'warning' : 'info'
            )
            
            setResults(attackResults)
            setIsRunning(false)
            
            // 延迟显示报告
            setTimeout(() => {
              setPhase('report')
              if (breached > 0) {
                setTimeout(() => setShowEmailModal(true), 1000)
              }
            }, 1500)
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
      { id: 0, text: 'AntiClaude Attack Engine v1.0.0', type: 'system' },
      { id: 1, text: 'Ready. Waiting for target...', type: 'info' }
    ])
    setLineId(2)
  }

  const score = calculateSecurityScore(results)
  const vulnerabilityCount = results.filter(r => r.leaked).length

  return (
    <div className="min-h-screen bg-background">
      {/* Grid Background */}
      <div className="fixed inset-0 bg-[linear-gradient(rgba(255,255,255,.02)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,.02)_1px,transparent_1px)] bg-[size:64px_64px] pointer-events-none" />
      
      <main className="relative z-10">
        {/* Header */}
        <header className="border-b border-border bg-background/80 backdrop-blur-sm sticky top-0 z-20">
          <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield className="w-6 h-6 text-primary" />
              <span className="font-bold text-foreground">AntiClaude</span>
            </div>
            <div className="flex items-center gap-4">
              <a 
                href="https://github.com" 
                target="_blank" 
                rel="noopener noreferrer"
                className="text-muted-foreground hover:text-foreground transition-colors"
              >
                <Github className="w-5 h-5" />
              </a>
              <a 
                href="https://twitter.com" 
                target="_blank" 
                rel="noopener noreferrer"
                className="text-muted-foreground hover:text-foreground transition-colors"
              >
                <Twitter className="w-5 h-5" />
              </a>
            </div>
          </div>
        </header>

        {/* Main Content */}
        <div className="max-w-6xl mx-auto px-4 py-12">
          {phase === 'input' && (
            <>
              <HeroSection />
              <div className="max-w-xl mx-auto">
                <AttackForm onStartAttack={handleStartAttack} isRunning={isRunning} />
              </div>
            </>
          )}

          {phase === 'attacking' && (
            <div className="max-w-4xl mx-auto">
              <div className="text-center mb-8">
                <h2 className="text-2xl font-bold text-foreground mb-2">
                  Attack in Progress
                </h2>
                <p className="text-muted-foreground">
                  Testing your AI for prompt injection vulnerabilities...
                </p>
              </div>
              <AttackTerminal 
                lines={terminalLines} 
                isRunning={isRunning} 
              />
            </div>
          )}

          {phase === 'report' && (
            <div className="max-w-2xl mx-auto">
              <div className="flex items-center justify-between mb-8">
                <div>
                  <h2 className="text-2xl font-bold text-foreground">
                    Security Report
                  </h2>
                  <p className="text-muted-foreground">
                    Analysis complete. Review your results below.
                  </p>
                </div>
                <button 
                  onClick={handleNewTest}
                  className="flex items-center gap-2 text-sm text-primary hover:text-primary/80 transition-colors"
                >
                  Run New Test <ArrowRight className="w-4 h-4" />
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
          <div className="max-w-7xl mx-auto px-4 py-8">
            <div className="flex flex-col md:flex-row items-center justify-between gap-4">
              <div className="flex items-center gap-2">
                <Shield className="w-5 h-5 text-primary" />
                <span className="text-sm text-muted-foreground">
                  AntiClaude - LLM Security Testing Platform
                </span>
              </div>
              <p className="text-sm text-muted-foreground">
                Built for AI developers who care about security.
              </p>
            </div>
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
