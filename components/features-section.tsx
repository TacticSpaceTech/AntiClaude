'use client'

import { useEffect, useRef, useState } from 'react'
import { useI18n } from '@/lib/i18n'
import { Shield, Zap, FileText, Code2, Lock, RefreshCw } from 'lucide-react'

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

export function FeaturesSection() {
  const { t } = useI18n()
  const sectionRef = useRef<HTMLDivElement>(null)
  const visible = useScrollReveal(sectionRef)

  const features = [
    {
      icon: Shield,
      titleKey: 'features.scan' as const,
      descKey: 'features.scanDesc' as const,
    },
    {
      icon: Zap,
      titleKey: 'features.realtime' as const,
      descKey: 'features.realtimeDesc' as const,
    },
    {
      icon: FileText,
      titleKey: 'features.report' as const,
      descKey: 'features.reportDesc' as const,
    },
    {
      icon: Code2,
      titleKey: 'features.nocode' as const,
      descKey: 'features.nocodeDesc' as const,
    },
    {
      icon: Lock,
      titleKey: 'features.enterprise' as const,
      descKey: 'features.enterpriseDesc' as const,
    },
    {
      icon: RefreshCw,
      titleKey: 'features.cicd' as const,
      descKey: 'features.cicdDesc' as const,
    }
  ]

  return (
    <section className="py-24 border-t border-primary/10 relative">
      {/* Background glow */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,_rgba(0,255,65,0.03)_0%,_transparent_50%)]" />

      <div className="max-w-5xl mx-auto px-6 relative">
        <div className="text-center mb-16">
          <p className="text-sm font-mono text-primary/60 mb-3 tracking-wider">
            {'// '}{t('features.label')}
          </p>
          <h2 className="text-3xl md:text-4xl font-bold text-foreground mb-4 text-balance">
            {t('features.title')}
          </h2>
          <p className="text-lg text-muted-foreground max-w-2xl mx-auto text-pretty">
            {t('features.subtitle')}
          </p>
        </div>

        <div ref={sectionRef} className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          {features.map((feature, index) => (
            <div
              key={feature.titleKey}
              className={`group p-6 rounded-lg bg-card/80 backdrop-blur-sm border border-border hover:border-primary/40 transition-all hover:shadow-sm ${visible ? 'animate-in fade-in slide-in-from-bottom-4 duration-500 fill-mode-both' : 'opacity-0'}`}
              style={{ animationDelay: `${index * 100}ms` }}
            >
              <div className="w-10 h-10 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center mb-4 group-hover:bg-primary/20 group-hover:border-primary/40 transition-all group-hover:shadow-[0_0_15px_rgba(0,255,65,0.2)]">
                <feature.icon className="w-5 h-5 text-primary" />
              </div>
              <h3 className="text-lg font-semibold text-foreground mb-2 font-mono">
                {t(feature.titleKey)}
              </h3>
              <p className="text-sm text-muted-foreground leading-relaxed">
                {t(feature.descKey)}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
