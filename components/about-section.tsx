'use client'

import { useI18n } from '@/lib/i18n'

export function AboutSection() {
  const { t } = useI18n()
  
  return (
    <section className="py-24 border-t border-border">
      <div className="max-w-5xl mx-auto px-6">
        <div className="grid lg:grid-cols-2 gap-16 items-center">
          {/* Left: Vision */}
          <div>
            <p className="text-sm font-medium text-muted-foreground mb-3 tracking-wide uppercase">
              {t('about.label')}
            </p>
            <h2 className="text-3xl md:text-4xl font-bold text-foreground mb-6 text-balance">
              {t('about.title')}
            </h2>
            <div className="space-y-4 text-muted-foreground leading-relaxed">
              <p>
                {t('about.p1')}
              </p>
              <p>
                {t('about.p2')}
              </p>
              <p>
                {t('about.p3')}
              </p>
            </div>
          </div>
          
          {/* Right: Stats & Mission */}
          <div className="space-y-8">
            {/* Mission Card */}
            <div className="p-6 rounded-xl bg-card border border-border">
              <h3 className="text-lg font-semibold text-foreground mb-3">
                {t('about.missionTitle')}
              </h3>
              <p className="text-muted-foreground text-sm leading-relaxed">
                {t('about.missionText')}
              </p>
            </div>
            
            {/* Stats Grid */}
            <div className="grid grid-cols-2 gap-4">
              <div className="p-6 rounded-xl bg-card border border-border text-center">
                <p className="text-3xl font-bold text-foreground mb-1">87%</p>
                <p className="text-sm text-muted-foreground">{t('about.stat1')}</p>
              </div>
              <div className="p-6 rounded-xl bg-card border border-border text-center">
                <p className="text-3xl font-bold text-foreground mb-1">12+</p>
                <p className="text-sm text-muted-foreground">{t('about.stat2')}</p>
              </div>
              <div className="p-6 rounded-xl bg-card border border-border text-center">
                <p className="text-3xl font-bold text-foreground mb-1">30s</p>
                <p className="text-sm text-muted-foreground">{t('about.stat3')}</p>
              </div>
              <div className="p-6 rounded-xl bg-card border border-border text-center">
                <p className="text-3xl font-bold text-foreground mb-1">100%</p>
                <p className="text-sm text-muted-foreground">{t('about.stat4')}</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}
