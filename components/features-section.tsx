'use client'

import { useI18n } from '@/lib/i18n'
import { Shield, Zap, FileText, Code2, Lock, RefreshCw } from 'lucide-react'

export function FeaturesSection() {
  const { t } = useI18n()
  
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
    <section className="py-24 border-t border-border">
      <div className="max-w-5xl mx-auto px-6">
        <div className="text-center mb-16">
          <p className="text-sm font-medium text-muted-foreground mb-3 tracking-wide uppercase">
            {t('features.label')}
          </p>
          <h2 className="text-3xl md:text-4xl font-bold text-foreground mb-4 text-balance">
            {t('features.title')}
          </h2>
          <p className="text-lg text-muted-foreground max-w-2xl mx-auto text-pretty">
            {t('features.subtitle')}
          </p>
        </div>
        
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          {features.map((feature) => (
            <div 
              key={feature.titleKey}
              className="group p-6 rounded-xl bg-card border border-border hover:border-foreground/20 transition-colors"
            >
              <div className="w-10 h-10 rounded-lg bg-secondary flex items-center justify-center mb-4 group-hover:bg-foreground/10 transition-colors">
                <feature.icon className="w-5 h-5 text-foreground" />
              </div>
              <h3 className="text-lg font-semibold text-foreground mb-2">
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
