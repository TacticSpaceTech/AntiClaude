'use client'

import { useI18n } from '@/lib/i18n'

export function HowItWorksSection() {
  const { t } = useI18n()
  
  const steps = [
    { number: '01', titleKey: 'howItWorks.step1' as const, descKey: 'howItWorks.step1Desc' as const },
    { number: '02', titleKey: 'howItWorks.step2' as const, descKey: 'howItWorks.step2Desc' as const },
    { number: '03', titleKey: 'howItWorks.step3' as const, descKey: 'howItWorks.step3Desc' as const },
    { number: '04', titleKey: 'howItWorks.step4' as const, descKey: 'howItWorks.step4Desc' as const },
  ]

  return (
    <section className="py-24 border-t border-border bg-card/50">
      <div className="max-w-5xl mx-auto px-6">
        <div className="text-center mb-16">
          <p className="text-sm font-medium text-muted-foreground mb-3 tracking-wide uppercase">
            {t('howItWorks.label')}
          </p>
          <h2 className="text-3xl md:text-4xl font-bold text-foreground mb-4 text-balance">
            {t('howItWorks.title')}
          </h2>
          <p className="text-lg text-muted-foreground max-w-2xl mx-auto text-pretty">
            {t('howItWorks.subtitle')}
          </p>
        </div>
        
        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-8">
          {steps.map((step, index) => (
            <div key={step.number} className="relative">
              {index < steps.length - 1 && (
                <div className="hidden lg:block absolute top-6 left-full w-full h-px bg-border -translate-x-4" />
              )}
              <div className="text-4xl font-bold text-border mb-4">
                {step.number}
              </div>
              <h3 className="text-lg font-semibold text-foreground mb-2">
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
