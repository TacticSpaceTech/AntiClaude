'use client'

import { useState, useCallback, useRef } from 'react'
import { HeroSection } from '@/components/hero-section'
import { AttackForm, type AttackConfig } from '@/components/attack-form'
import { AttackTerminal } from '@/components/attack-terminal'
import { SecurityReport, type AttackResult } from '@/components/security-report'
import { EmailCaptureModal } from '@/components/email-capture-modal'
import { FeaturesSection } from '@/components/features-section'
import { HowItWorksSection } from '@/components/how-it-works-section'
import { AboutSection } from '@/components/about-section'
import { AttackVectorsSection } from '@/components/attack-vectors-section'
import { FAQSection } from '@/components/faq-section'
import { CTASection } from '@/components/cta-section'
import { calculateSecurityScore } from '@/lib/payloads'
import { RotateCcw, Github, Menu, X } from 'lucide-react'

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
    { id: 1, text: '等待目标...', type: 'info' }
  ])
  const [results, setResults] = useState<AttackResult[]>([])
  const [isReportLocked, setIsReportLocked] = useState(true)
  const [showEmailModal, setShowEmailModal] = useState(false)
  const [lineId, setLineId] = useState(2)
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const testSectionRef = useRef<HTMLDivElement>(null)

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

    addLine(`目标: ${config.endpoint}`, 'info')
    addLine('正在初始化扫描...', 'system')

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
            addLine(`已加载 ${data.totalPayloads} 个攻击载荷`, 'info')
          }

          if (data.type === 'attack_start') {
            addLine(`测试中: ${data.payload.name}`, 'attack')
          }

          if (data.type === 'attack_result') {
            const result = data.result as AttackResult
            attackResults.push(result)
            
            if (result.leaked) {
              addLine(`发现漏洞 (置信度 ${result.confidence}%)`, 'success')
            } else {
              addLine(`测试通过 - 未发现漏洞`, 'error')
            }
          }

          if (data.type === 'complete') {
            const breached = attackResults.filter(r => r.leaked).length
            addLine('扫描完成', 'system')
            addLine(`结果: 发现 ${breached}/${attackResults.length} 个漏洞`, 
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
      addLine(`错误: ${error instanceof Error ? error.message : '未知错误'}`, 'error')
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
      { id: 1, text: '等待目标...', type: 'info' }
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
    <div className="min-h-screen bg-background">
      <main className="relative">
        {/* Header */}
        <header className="border-b border-border bg-background/80 backdrop-blur-md sticky top-0 z-50">
          <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-foreground flex items-center justify-center">
                <span className="text-background font-bold text-sm">A</span>
              </div>
              <span className="font-semibold text-foreground text-lg">AntiClaude</span>
            </div>
            
            {/* Desktop Nav */}
            <nav className="hidden md:flex items-center gap-8">
              <button 
                onClick={scrollToTest}
                className="text-sm text-muted-foreground hover:text-foreground transition-colors"
              >
                开始测试
              </button>
              <a href="#features" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                功能特性
              </a>
              <a href="#about" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                关于我们
              </a>
              <a href="#faq" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                常见问题
              </a>
            </nav>
            
            <div className="hidden md:flex items-center gap-4">
              <a 
                href="https://github.com" 
                target="_blank" 
                rel="noopener noreferrer"
                className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
              >
                <Github className="w-4 h-4" />
                GitHub
              </a>
              <button 
                onClick={scrollToTest}
                className="px-4 py-2 bg-foreground text-background text-sm font-medium rounded-lg hover:bg-foreground/90 transition-colors"
              >
                免费试用
              </button>
            </div>
            
            {/* Mobile Menu Button */}
            <button 
              className="md:hidden p-2"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            >
              {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
          
          {/* Mobile Menu */}
          {mobileMenuOpen && (
            <div className="md:hidden border-t border-border bg-background py-4 px-6 space-y-4">
              <button 
                onClick={scrollToTest}
                className="block w-full text-left text-sm text-muted-foreground hover:text-foreground"
              >
                开始测试
              </button>
              <a href="#features" className="block text-sm text-muted-foreground hover:text-foreground">
                功能特性
              </a>
              <a href="#about" className="block text-sm text-muted-foreground hover:text-foreground">
                关于我们
              </a>
              <a href="#faq" className="block text-sm text-muted-foreground hover:text-foreground">
                常见问题
              </a>
              <button 
                onClick={scrollToTest}
                className="w-full px-4 py-2 bg-foreground text-background text-sm font-medium rounded-lg"
              >
                免费试用
              </button>
            </div>
          )}
        </header>

        {/* Test Section */}
        <section ref={testSectionRef} className="py-20">
          <div className="max-w-2xl mx-auto px-6">
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
                    正在扫描中
                  </h2>
                  <p className="text-sm text-muted-foreground">
                    正在测试提示词注入漏洞...
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
                      安全报告
                    </h2>
                    <p className="text-sm text-muted-foreground">
                      扫描完成，请查看结果
                    </p>
                  </div>
                  <button 
                    onClick={handleNewTest}
                    className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
                  >
                    <RotateCcw className="w-4 h-4" />
                    新扫描
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
        <footer className="border-t border-border bg-card/50">
          <div className="max-w-6xl mx-auto px-6 py-12">
            <div className="grid md:grid-cols-4 gap-8 mb-12">
              {/* Brand */}
              <div className="md:col-span-2">
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-8 h-8 rounded-lg bg-foreground flex items-center justify-center">
                    <span className="text-background font-bold text-sm">A</span>
                  </div>
                  <span className="font-semibold text-foreground text-lg">AntiClaude</span>
                </div>
                <p className="text-sm text-muted-foreground max-w-xs leading-relaxed">
                  面向 AI 开发者的自动化渗透测试平台。在攻击者之前发现漏洞，保护你的 AI 应用安全。
                </p>
              </div>
              
              {/* Links */}
              <div>
                <h4 className="font-medium text-foreground mb-4">产品</h4>
                <ul className="space-y-2 text-sm text-muted-foreground">
                  <li><button onClick={scrollToTest} className="hover:text-foreground transition-colors">安全扫描</button></li>
                  <li><span className="text-muted-foreground/50">CI/CD 集成 (即将推出)</span></li>
                  <li><span className="text-muted-foreground/50">企业版 (即将推出)</span></li>
                </ul>
              </div>
              
              <div>
                <h4 className="font-medium text-foreground mb-4">资源</h4>
                <ul className="space-y-2 text-sm text-muted-foreground">
                  <li><a href="#" className="hover:text-foreground transition-colors">文档</a></li>
                  <li><a href="#" className="hover:text-foreground transition-colors">博客</a></li>
                  <li><a href="https://github.com" className="hover:text-foreground transition-colors">GitHub</a></li>
                </ul>
              </div>
            </div>
            
            <div className="pt-8 border-t border-border flex flex-col md:flex-row items-center justify-between gap-4">
              <p className="text-xs text-muted-foreground">
                2024 AntiClaude. All rights reserved.
              </p>
              <div className="flex items-center gap-6 text-xs text-muted-foreground">
                <a href="#" className="hover:text-foreground transition-colors">隐私政策</a>
                <a href="#" className="hover:text-foreground transition-colors">服务条款</a>
                <a href="#" className="hover:text-foreground transition-colors">联系我们</a>
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
