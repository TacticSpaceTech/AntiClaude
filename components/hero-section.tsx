'use client'

import { useEffect, useState } from 'react'
import { Zap, Github } from 'lucide-react'
import { useI18n } from '@/lib/i18n'

// Typewriter effect hook
function useTypewriter(text: string, speed: number = 50, delay: number = 0) {
  const [displayText, setDisplayText] = useState('')
  const [isComplete, setIsComplete] = useState(false)

  useEffect(() => {
    setDisplayText('')
    setIsComplete(false)

    const timeout = setTimeout(() => {
      let index = 0
      const interval = setInterval(() => {
        if (index < text.length) {
          setDisplayText(text.slice(0, index + 1))
          index++
        } else {
          setIsComplete(true)
          clearInterval(interval)
        }
      }, speed)

      return () => clearInterval(interval)
    }, delay)

    return () => clearTimeout(timeout)
  }, [text, speed, delay])

  return { displayText, isComplete }
}

// Glitch text effect
function GlitchText({ children, className }: { children: string; className?: string }) {
  const [glitchText, setGlitchText] = useState(children)

  useEffect(() => {
    const chars = 'アイウエオカキクケコ0123456789!@#$%'
    let glitchInterval: NodeJS.Timeout

    const glitch = () => {
      const randomIndex = Math.floor(Math.random() * children.length)
      const randomChar = chars[Math.floor(Math.random() * chars.length)]
      const newText = children.slice(0, randomIndex) + randomChar + children.slice(randomIndex + 1)
      setGlitchText(newText)

      setTimeout(() => setGlitchText(children), 100)
    }

    glitchInterval = setInterval(glitch, 3000 + Math.random() * 2000)

    return () => clearInterval(glitchInterval)
  }, [children])

  return <span className={className}>{glitchText}</span>
}

interface HeroSectionProps {
  onScrollToScan?: () => void
}

export function HeroSection({ onScrollToScan }: HeroSectionProps) {
  const { t } = useI18n()
  const [mounted, setMounted] = useState(false)

  const terminalLine1 = useTypewriter('> initializing_anticlaude_v2.0...', 30, 500)
  const terminalLine2 = useTypewriter('> loading_attack_vectors: [████████████] 100%', 20, 2000)
  const terminalLine3 = useTypewriter('> system_ready. awaiting_target...', 30, 4000)

  useEffect(() => {
    setMounted(true)
  }, [])

  if (!mounted) return null

  return (
    <div className="relative z-10 text-center mb-16 pt-8">
      {/* Terminal-style intro */}
      <div className="max-w-2xl mx-auto mb-12 text-left font-mono text-sm">
        <div className="bg-black/60 backdrop-blur-sm border border-primary/30 rounded-lg p-4 shadow-[0_0_30px_rgba(0,255,65,0.15)]">
          <div className="flex items-center gap-2 mb-3 pb-2 border-b border-primary/20">
            <div className="w-3 h-3 rounded-full bg-danger" />
            <div className="w-3 h-3 rounded-full bg-warning" />
            <div className="w-3 h-3 rounded-full bg-primary" />
            <span className="ml-2 text-muted-foreground text-xs">anticlaude@terminal</span>
          </div>
          <div className="space-y-1">
            <p className="text-primary">
              {terminalLine1.displayText}
              {!terminalLine1.isComplete && <span className="animate-pulse">_</span>}
            </p>
            <p className="text-primary/80">
              {terminalLine2.displayText}
              {terminalLine1.isComplete && !terminalLine2.isComplete && <span className="animate-pulse">_</span>}
            </p>
            <p className="text-primary">
              {terminalLine3.displayText}
              {terminalLine2.isComplete && !terminalLine3.isComplete && <span className="animate-pulse">_</span>}
              {terminalLine3.isComplete && <span className="animate-pulse">█</span>}
            </p>
          </div>
        </div>
      </div>

      {/* Badge */}
      <div className="inline-flex items-center gap-2 px-4 py-2 mb-8 text-xs font-mono rounded border border-primary/40 bg-primary/5 text-primary shadow-[0_0_15px_rgba(0,255,65,0.2)]">
        <span className="w-2 h-2 rounded-full bg-primary animate-pulse shadow-[0_0_10px_rgba(0,255,65,0.8)]" />
        {t('hero.badge')}
      </div>

      {/* Main Headline */}
      <h1 className="text-4xl md:text-5xl lg:text-7xl font-bold text-foreground mb-6 leading-tight tracking-tight text-balance">
        <GlitchText className="block">{t('hero.title')}</GlitchText>
        <span className="block mt-2 bg-gradient-to-r from-primary via-[#00ff41] to-[#39ff14] bg-clip-text text-transparent drop-shadow-[0_0_20px_rgba(0,255,65,0.4)]">
          {t('hero.titleHighlight')}
        </span>
      </h1>

      {/* Subtitle */}
      <p className="text-lg md:text-xl text-muted-foreground max-w-2xl mx-auto mb-4 leading-relaxed text-pretty font-mono">
        {t('hero.subtitle')}
      </p>

      <p className="text-sm text-muted-foreground/70 max-w-xl mx-auto mb-12 font-mono">
        {'// '}{t('hero.description')}
      </p>

      {/* Trust Bar */}
      <div className="flex items-center justify-center gap-6 mt-8 mb-2 flex-wrap">
        <span className="text-xs text-primary/40 font-mono flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-primary/60" />
          {t('hero.trustOwasp')}
        </span>
        <span className="text-xs text-primary/40 font-mono flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-primary/60" />
          {t('hero.trustOpen')}
        </span>
        <span className="text-xs text-primary/40 font-mono flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-primary/60" />
          {t('hero.trustNpm')}
        </span>
      </div>

      {/* Stats with Matrix styling */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 max-w-3xl mx-auto mt-6">
        {[
          { value: '64', label: t('hero.stat1') },
          { value: '7', label: t('hero.stat2') },
          { value: '<30s', label: t('hero.stat3') },
          { value: t('hero.stat4Value'), label: t('hero.stat4') },
        ].map((stat, index) => (
          <div
            key={index}
            className="relative p-4 rounded border border-primary/20 bg-black/40 backdrop-blur-sm group hover:border-primary/50 transition-all duration-300"
          >
            <div className="absolute inset-0 bg-primary/5 opacity-0 group-hover:opacity-100 transition-opacity rounded" />
            <p className="text-2xl md:text-3xl font-bold text-primary font-mono">
              {stat.value}
            </p>
            <p className="text-xs text-muted-foreground mt-1 font-mono">{stat.label}</p>
          </div>
        ))}
      </div>

      {/* CTA Buttons */}
      <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mt-10">
        <button
          onClick={onScrollToScan}
          className="px-8 py-3 bg-primary text-primary-foreground font-mono font-bold rounded-lg
                     shadow-lg hover:shadow-xl
                     hover:bg-primary/90 transition-all duration-300 flex items-center gap-2"
        >
          <Zap className="w-4 h-4" />
          {t('hero.ctaButton')}
        </button>
        <a
          href="https://github.com/TacticSpaceTech/AntiClaude"
          target="_blank"
          rel="noopener noreferrer"
          className="px-6 py-3 border border-primary/30 text-primary/70 font-mono rounded-lg
                     hover:border-primary/60 hover:text-primary transition-all duration-300
                     flex items-center gap-2 text-sm"
        >
          <Github className="w-4 h-4" />
          {t('hero.ctaSecondary')}
        </a>
      </div>

      {/* Decorative elements */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-px h-20 bg-gradient-to-b from-transparent via-primary/50 to-transparent" />
    </div>
  )
}
