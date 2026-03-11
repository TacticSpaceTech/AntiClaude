'use client'

import { useEffect, useRef, useState } from 'react'
import { useI18n } from '@/lib/i18n'

function useScrollReveal(ref: React.RefObject<Element | null>) {
  const [visible, setVisible] = useState(false)
  useEffect(() => {
    const obs = new IntersectionObserver(
      ([entry]) => { if (entry.isIntersecting) setVisible(true) },
      { threshold: 0.1 }
    )
    if (ref.current) obs.observe(ref.current)
    return () => obs.disconnect()
  }, [ref])
  return visible
}

export function HowItWorksSection() {
  const { t } = useI18n()
  const sectionRef = useRef<HTMLDivElement>(null)
  const visible = useScrollReveal(sectionRef)

  const steps = [
    { number: '01', titleKey: 'howItWorks.step1' as const, descKey: 'howItWorks.step1Desc' as const },
    { number: '02', titleKey: 'howItWorks.step2' as const, descKey: 'howItWorks.step2Desc' as const },
    { number: '03', titleKey: 'howItWorks.step3' as const, descKey: 'howItWorks.step3Desc' as const },
    { number: '04', titleKey: 'howItWorks.step4' as const, descKey: 'howItWorks.step4Desc' as const },
  ]

  return (
    <section className="py-24 border-t border-primary/10 bg-black/20 relative">
      {/* Scan line effect */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute w-full h-px bg-gradient-to-r from-transparent via-primary/30 to-transparent animate-pulse" style={{ top: '30%' }} />
      </div>

      <div className="max-w-5xl mx-auto px-6 relative">
        <div className="text-center mb-16">
          <p className="text-sm font-mono text-primary/60 mb-3 tracking-wider">
            {'// '}{t('howItWorks.label')}
          </p>
          <h2 className="text-3xl md:text-4xl font-bold text-foreground mb-4 text-balance">
            {t('howItWorks.title')}
          </h2>
          <p className="text-lg text-muted-foreground max-w-2xl mx-auto text-pretty">
            {t('howItWorks.subtitle')}
          </p>
        </div>

        <div ref={sectionRef} className="grid md:grid-cols-2 lg:grid-cols-4 gap-8">
          {steps.map((step, index) => (
            <div
              key={step.number}
              className={`relative group ${visible ? 'animate-in fade-in slide-in-from-bottom-4 duration-500 fill-mode-both' : 'opacity-0'}`}
              style={{ animationDelay: `${index * 150}ms` }}
            >
              {/* Connector line */}
              {index < steps.length - 1 && (
                <div className="hidden lg:block absolute top-8 left-full w-full h-px bg-gradient-to-r from-primary/30 to-transparent -translate-x-4" />
              )}

              {/* Step number */}
              <div className="text-5xl font-bold font-mono text-primary/20 mb-4 group-hover:text-primary/40 transition-colors drop-shadow-[0_0_10px_rgba(0,255,65,0.1)] group-hover:drop-shadow-[0_0_15px_rgba(0,255,65,0.2)]">
                {step.number}
              </div>

              <h3 className="text-lg font-semibold text-foreground mb-2 font-mono">
                {t(step.titleKey)}
              </h3>
              <p className="text-sm text-muted-foreground leading-relaxed">
                {t(step.descKey)}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
