'use client'

import { useState, useCallback, useRef, useEffect } from 'react'
import { I18nProvider, useI18n } from '@/lib/i18n'
import { HeroSection } from '@/components/hero-section'
import { MatrixRain } from '@/components/matrix-rain'
import { AttackForm, type AttackConfig } from '@/components/attack-form'
import { AttackTerminal, type TerminalLine } from '@/components/attack-terminal'
import { AIBattleTerminal, type BattleLine } from '@/components/ai-battle-terminal'
import { SecurityReport, type AttackResult } from '@/components/security-report'
import { EmailCaptureModal } from '@/components/email-capture-modal'
import { FeaturesSection } from '@/components/features-section'
import { HowItWorksSection } from '@/components/how-it-works-section'
import { AboutSection } from '@/components/about-section'
import { AttackVectorsSection } from '@/components/attack-vectors-section'
import { FAQSection } from '@/components/faq-section'
import { CTASection } from '@/components/cta-section'
import { LanguageSwitcher } from '@/components/language-switcher'
import { calculateSecurityScore } from '@/lib/payloads'
import { RotateCcw, Github, Menu, X } from 'lucide-react'

type AppPhase = 'input' | 'attacking' | 'report'

function HomeContent() {
  const { t, locale } = useI18n()
  const [phase, setPhase] = useState<AppPhase>('input')
  const [isRunning, setIsRunning] = useState(false)
  const [terminalLines, setTerminalLines] = useState<TerminalLine[]>([
    { id: 0, text: 'AntiClaude Security Scanner v1.0', type: 'system' },
    { id: 1, text: t('terminal.waiting'), type: 'info' }
  ])
  const [results, setResults] = useState<AttackResult[]>([])
  const [isReportLocked, setIsReportLocked] = useState(true)
  const [showEmailModal, setShowEmailModal] = useState(false)
  const [lineId, setLineId] = useState(2)
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const [battleLines, setBattleLines] = useState<BattleLine[]>([])
  const [battleLineId, setBattleLineId] = useState(0)
  const [currentStrategy, setCurrentStrategy] = useState<string>('direct')
  const [defenderStatus, setDefenderStatus] = useState<'analyzing' | 'blocking' | 'vulnerable' | 'idle'>('idle')
  const [targetEndpoint, setTargetEndpoint] = useState('')
  const testSectionRef = useRef<HTMLDivElement>(null)
  const abortControllerRef = useRef<AbortController | null>(null)

  const addBattleLine = useCallback((
    source: BattleLine['source'],
    text: string,
    extra?: { thinking?: string; confidence?: number; isStreaming?: boolean }
  ) => {
    const timestamp = new Date().toLocaleTimeString('en-US', { 
      hour12: false, 
      hour: '2-digit', 
      minute: '2-digit', 
      second: '2-digit' 
    })
    setBattleLineId(prev => {
      setBattleLines(lines => [...lines, { 
        id: prev, 
        source,
        text, 
        timestamp,
        ...extra
      }])
      return prev + 1
    })
  }, [])

  const addLine = useCallback((
    text: string, 
    type: TerminalLine['type'],
    extra?: { details?: string; confidence?: number; indicators?: string[] }
  ) => {
    const timestamp = new Date().toLocaleTimeString('en-US', { 
      hour12: false, 
      hour: '2-digit', 
      minute: '2-digit', 
      second: '2-digit' 
    })
    setLineId(prev => {
      setTerminalLines(lines => [...lines, { 
        id: prev, 
        text, 
        type, 
        timestamp,
        ...extra
      }])
      return prev + 1
    })
  }, [])

  useEffect(() => {
    return () => {
      abortControllerRef.current?.abort()
    }
  }, [])

  const handleStopAttack = () => {
    abortControllerRef.current?.abort()
  }

  const handleStartAttack = async (config: AttackConfig) => {
    const controller = new AbortController()
    abortControllerRef.current = controller
    setPhase('attacking')
    setIsRunning(true)
    setResults([])
    setTargetEndpoint(config.endpoint)
    setTerminalLines([
      { id: 0, text: 'AntiClaude Security Scanner v1.0', type: 'system' },
    ])
    setBattleLines([])
    setBattleLineId(0)
    setDefenderStatus('idle')
    setLineId(1)

    addLine(`${t('terminal.target')}: ${config.endpoint}`, 'info')
    addLine(t('terminal.initializing'), 'system')
    
    // AI Battle initialization
    addBattleLine('system', locale === 'zh' ? '初始化 AI 对抗系统...' : 'Initializing AI Battle System...', { thinking: locale === 'zh' ? '加载攻击模块' : 'Loading attack modules' })
    addBattleLine('attacker', locale === 'zh' ? '目标锁定: ' + config.endpoint : 'Target acquired: ' + config.endpoint, { thinking: locale === 'zh' ? '分析目标架构...' : 'Analyzing target architecture...' })

    try {
      const response = await fetch('/api/attack/stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          endpoint: config.endpoint,
          authHeader: config.authHeader,
          payloadCount: 6
        }),
        signal: controller.signal
      })

      if (!response.body) {
        throw new Error('No response body')
      }

      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      const attackResults: AttackResult[] = []
      let sseBuffer = ''

      while (true) {
        const { done, value } = await reader.read()
        if (done) break

        sseBuffer += decoder.decode(value, { stream: true })
        const frames = sseBuffer.split('\n\n')
        sseBuffer = frames.pop() ?? ''

        for (const frame of frames) {
          if (!frame.startsWith('data: ')) continue
          const jsonStr = frame.slice(6).trim()
          if (!jsonStr) continue
          let data: any
          try {
            data = JSON.parse(jsonStr)
          } catch {
            continue
          }

          if (data.type === 'init') {
            addLine(t('terminal.loaded', { count: data.totalPayloads }), 'info')
          }

          if (data.type === 'attack_start') {
            addLine(
              `${t('terminal.testing')}: ${data.payload.name} [${data.payload.severity.toUpperCase()}]`,
              'attack',
              { details: data.payload.prompt }
            )

            // AI Battle: Attacker move
            setDefenderStatus('analyzing')
            const strategy = data.result?.strategy || 'direct'
            setCurrentStrategy(strategy)
            addBattleLine('attacker', `[${data.payload.severity.toUpperCase()}] ${data.payload.name}`, {
              thinking: locale === 'zh' ? '选择攻击策略: ' + strategy : 'Selecting strategy: ' + strategy,
              isStreaming: true
            })
          }

          if (data.type === 'strategy_selected') {
            const strategy = data.strategy as string
            setCurrentStrategy(strategy)
            addLine(`Strategy: ${strategy} → ${data.payloadName}`, 'info')
            addBattleLine('attacker', locale === 'zh' ? `切换策略: ${strategy}` : `Switching strategy: ${strategy}`, {
              thinking: locale === 'zh' ? '调整攻击角度...' : 'Adjusting attack vector...',
              isStreaming: true
            })
          }

          if (data.type === 'error') {
            addLine(`Error: ${data.message}`, 'warning')
          }

          if (data.type === 'attack_result') {
            const result = data.result as AttackResult
            attackResults.push(result)

            if (result.leaked) {
              addLine(
                t('terminal.vulnerability', { confidence: result.confidence }),
                'success',
                {
                  confidence: result.confidence,
                  indicators: result.indicators,
                  details: result.response?.slice(0, 150)
                }
              )

              // AI Battle: Successful breach
              setDefenderStatus('vulnerable')
              addBattleLine('defender', locale === 'zh' ? '防线被突破!' : 'Defense breached!', { confidence: 100 - result.confidence })
              addBattleLine('result', `[LEAK] ${locale === 'zh' ? '置信度' : 'Confidence'}: ${result.confidence}%`, { confidence: result.confidence })
            } else if (result.error) {
              addLine(`API Error: ${result.error}`, 'warning')
            } else {
              addLine(t('terminal.passed'), 'error')

              // AI Battle: Blocked
              setDefenderStatus('blocking')
              addBattleLine('defender', locale === 'zh' ? '攻击已拦截' : 'Attack blocked', { confidence: 100 })
              addBattleLine('result', `[SAFE] ${locale === 'zh' ? '防护有效' : 'Defense held'}`)
            }

            // Reset defender status after a short delay
            setTimeout(() => setDefenderStatus('idle'), 500)
          }

          if (data.type === 'complete') {
            const breached = attackResults.filter(r => r.leaked).length
            addLine(t('terminal.complete'), 'system')
            addLine(t('terminal.result', { found: breached, total: attackResults.length }),
              breached > 0 ? 'warning' : 'info'
            )

            setResults(attackResults)
            setIsRunning(false)
            abortControllerRef.current = null

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
      if (error instanceof Error && error.name === 'AbortError') {
        addLine('Scan cancelled.', 'warning')
      } else {
        addLine(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`, 'error')
      }
      setPhase('report')
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
      { id: 1, text: t('terminal.waiting'), type: 'info' }
    ])
    setLineId(2)
  }

  const scrollToTest = () => {
    testSectionRef.current?.scrollIntoView({ behavior: 'smooth' })
    setMobileMenuOpen(false)
  }

  const score = calculateSecurityScore(results)
  const vulnerabilityCount = results.filter(r => r.leaked).length

  return (
    <div className="min-h-screen bg-background relative overflow-hidden">
      {/* Matrix Rain Background */}
      <MatrixRain />
      
      <main className="relative z-10">
        {/* Header */}
        <header className="border-b border-primary/20 bg-background/90 backdrop-blur-md sticky top-0 z-50">
          <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <img src="/icon-192x192.png" alt="AntiClaude" className="w-8 h-8 rounded" />
              <span className="font-semibold text-primary text-lg font-mono">AntiClaude</span>
            </div>
            
            {/* Desktop Nav */}
            <nav className="hidden md:flex items-center gap-8">
              <button 
                onClick={scrollToTest}
                className="text-sm text-muted-foreground hover:text-foreground transition-colors"
              >
                {t('nav.startTest')}
              </button>
              <a href="#features" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                {t('nav.features')}
              </a>
              <a href="#about" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                {t('nav.about')}
              </a>
              <a href="#faq" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                {t('nav.faq')}
              </a>
            </nav>
            
            <div className="hidden md:flex items-center gap-3">
              <LanguageSwitcher />
              <a 
                href="https://github.com/TacticSpaceTech/AntiClaude" 
                target="_blank" 
                rel="noopener noreferrer"
                className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
              >
                <Github className="w-4 h-4" />
              </a>
              <button 
                onClick={scrollToTest}
                className="px-4 py-2 bg-primary text-primary-foreground text-sm font-medium rounded-lg hover:bg-primary/90 transition-colors shadow-[0_0_20px_rgba(0,255,65,0.3)] font-mono"
              >
                {t('nav.freeTrial')}
              </button>
            </div>
            
            {/* Mobile Menu Button */}
            <div className="flex md:hidden items-center gap-2">
              <LanguageSwitcher />
              <button 
                className="p-2"
                onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              >
                {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
              </button>
            </div>
          </div>
          
          {/* Mobile Menu */}
          {mobileMenuOpen && (
            <div className="md:hidden border-t border-border bg-background py-4 px-6 space-y-4">
              <button 
                onClick={scrollToTest}
                className="block w-full text-left text-sm text-muted-foreground hover:text-foreground"
              >
                {t('nav.startTest')}
              </button>
              <a href="#features" className="block text-sm text-muted-foreground hover:text-foreground">
                {t('nav.features')}
              </a>
              <a href="#about" className="block text-sm text-muted-foreground hover:text-foreground">
                {t('nav.about')}
              </a>
              <a href="#faq" className="block text-sm text-muted-foreground hover:text-foreground">
                {t('nav.faq')}
              </a>
              <button 
                onClick={scrollToTest}
                className="w-full px-4 py-2 bg-foreground text-background text-sm font-medium rounded-lg"
              >
                {t('nav.freeTrial')}
              </button>
            </div>
          )}
        </header>

        {/* Test Section */}
        <section ref={testSectionRef} className="py-20">
          <div className="max-w-2xl mx-auto px-6">
            {phase === 'input' && (
              <>
                <HeroSection onScrollToScan={scrollToTest} />
                <AttackForm onStartAttack={handleStartAttack} isRunning={isRunning} />
              </>
            )}

            {phase === 'attacking' && (
              <div className="space-y-6">
                <div className="text-center mb-4">
                  <h2 className="text-xl font-semibold text-foreground mb-2">
                    {t('scanning.title')}
                  </h2>
                  <p className="text-sm text-muted-foreground">
                    {t('scanning.subtitle')}
                  </p>
                  {isRunning && (
                    <div className="mt-3">
                      <button
                        onClick={handleStopAttack}
                        className="px-3 py-1 text-xs font-mono text-danger border border-danger/30 rounded hover:bg-danger/10 transition-colors"
                      >
                        {locale === 'zh' ? '停止扫描' : 'Stop Scan'}
                      </button>
                    </div>
                  )}
                </div>
                
                {/* AI Battle Terminal - Featured */}
                <AIBattleTerminal 
                  lines={battleLines}
                  isRunning={isRunning}
                  attackerStrategy={currentStrategy}
                  defenderStatus={defenderStatus}
                  currentPayload=""
                />
                
                {/* Classic Terminal - Collapsible */}
                <details className="group">
                  <summary className="cursor-pointer text-xs text-primary/50 font-mono flex items-center gap-2 hover:text-primary transition-colors">
                    <svg className="w-3 h-3 transition-transform group-open:rotate-90" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                    </svg>
                    {locale === 'zh' ? '查看详细日志' : 'View detailed logs'}
                  </summary>
                  <div className="mt-4">
                    <AttackTerminal 
                      lines={terminalLines} 
                      isRunning={isRunning} 
                    />
                  </div>
                </details>
              </div>
            )}

            {phase === 'report' && (
              <div>
                <div className="flex items-center justify-between mb-8">
                  <div>
                    <h2 className="text-xl font-semibold text-foreground">
                      {t('report.title')}
                    </h2>
                    <p className="text-sm text-muted-foreground">
                      {t('report.subtitle')}
                    </p>
                  </div>
                  <button 
                    onClick={handleNewTest}
                    className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
                  >
                    <RotateCcw className="w-4 h-4" />
                    {t('report.newScan')}
                  </button>
                </div>
                <SecurityReport 
                  score={score}
                  results={results}
                  endpoint={targetEndpoint}
                  isLocked={isReportLocked}
                  onUnlock={handleUnlockReport}
                />
              </div>
            )}
          </div>
        </section>

        {/* Features Section */}
        <div id="features">
          <FeaturesSection />
        </div>

        {/* How It Works */}
        <HowItWorksSection />

        {/* About Section */}
        <div id="about">
          <AboutSection />
        </div>

        {/* Attack Vectors */}
        <AttackVectorsSection />

        {/* FAQ Section */}
        <div id="faq">
          <FAQSection />
        </div>

        {/* CTA Section */}
        <CTASection onStartTest={scrollToTest} />

        {/* Footer */}
        <footer className="border-t border-primary/10 bg-black/40 backdrop-blur-sm">
          <div className="max-w-6xl mx-auto px-6 py-12">
            <div className="grid md:grid-cols-4 gap-8 mb-12">
              {/* Brand */}
              <div className="md:col-span-2">
                <div className="flex items-center gap-2.5 mb-4">
                  <img src="/icon-192x192.png" alt="AntiClaude" className="w-8 h-8 rounded" />
                  <span className="font-semibold text-primary text-lg font-mono">AntiClaude</span>
                </div>
                <p className="text-sm text-muted-foreground max-w-xs leading-relaxed">
                  {t('footer.description')}
                </p>
              </div>
              
              {/* Links */}
              <div>
                <h4 className="font-mono text-primary/70 mb-4 text-sm">{'// '}{t('footer.product')}</h4>
                <ul className="space-y-2 text-sm text-muted-foreground font-mono">
                  <li><button onClick={scrollToTest} className="hover:text-primary transition-colors">{t('footer.scan')}</button></li>
                  <li><a href="https://github.com/TacticSpaceTech/AntiClaude/discussions" target="_blank" rel="noopener noreferrer" className="hover:text-primary transition-colors">{t('footer.cicd')}</a></li>
                  <li><a href="https://github.com/TacticSpaceTech/AntiClaude/discussions" target="_blank" rel="noopener noreferrer" className="hover:text-primary transition-colors">{t('footer.enterprise')}</a></li>
                </ul>
              </div>
              
              <div>
                <h4 className="font-mono text-primary/70 mb-4 text-sm">{'// '}{t('footer.resources')}</h4>
                <ul className="space-y-2 text-sm text-muted-foreground font-mono">
                  <li><a href="/docs" className="hover:text-primary transition-colors">{t('nav.docs')}</a></li>
                  <li><a href="/blog" className="hover:text-primary transition-colors">{t('nav.blog')}</a></li>
                  <li><a href="https://github.com/TacticSpaceTech/AntiClaude" className="hover:text-primary transition-colors">GitHub</a></li>
                </ul>
              </div>
            </div>
            
            <div className="pt-8 border-t border-primary/10 flex flex-col md:flex-row items-center justify-between gap-4">
              <p className="text-xs text-primary/40 font-mono">
                {'// '}2026 AntiClaude. {t('footer.rights')}
              </p>
              <div className="flex items-center gap-6 text-xs text-muted-foreground font-mono">
                <a href="/privacy" className="hover:text-primary transition-colors">{t('footer.privacy')}</a>
                <a href="/terms" className="hover:text-primary transition-colors">{t('footer.terms')}</a>
                <a href="/contact" className="hover:text-primary transition-colors">{t('footer.contact')}</a>
              </div>
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

export default function Home() {
  return (
    <I18nProvider>
      <HomeContent />
    </I18nProvider>
  )
}
