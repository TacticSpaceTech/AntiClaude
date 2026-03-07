'use client'

import { useI18n } from '@/lib/i18n'

export function HeroSection() {
  const { t } = useI18n()
  
  return (
    <div className="text-center mb-16">
      {/* Badge */}
      <div className="inline-flex items-center gap-2 px-3 py-1.5 mb-8 text-xs font-medium rounded-full bg-secondary border border-border text-muted-foreground">
        <span className="w-1.5 h-1.5 rounded-full bg-success animate-pulse" />
        {t('hero.badge')}
      </div>

      {/* Main Headline */}
      <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold text-foreground mb-6 leading-tight tracking-tight text-balance">
        {t('hero.title')}
        <br />
        <span className="text-accent">{t('hero.titleHighlight')}</span>
      </h1>

      {/* Subtitle */}
      <p className="text-lg text-muted-foreground max-w-xl mx-auto mb-4 leading-relaxed text-pretty">
        {t('hero.subtitle')}
      </p>
      
      <p className="text-sm text-muted-foreground/80 max-w-lg mx-auto mb-10">
        {t('hero.description')}
      </p>

      {/* Stats */}
      <div className="flex flex-wrap justify-center gap-8 md:gap-12 pt-8 border-t border-border">
        <div className="text-center">
          <p className="text-2xl font-bold text-foreground">12+</p>
          <p className="text-sm text-muted-foreground">{t('hero.stat1')}</p>
        </div>
        <div className="text-center">
          <p className="text-2xl font-bold text-foreground">4</p>
          <p className="text-sm text-muted-foreground">{t('hero.stat2')}</p>
        </div>
        <div className="text-center">
          <p className="text-2xl font-bold text-foreground">{'<'}30s</p>
          <p className="text-sm text-muted-foreground">{t('hero.stat3')}</p>
        </div>
        <div className="text-center">
          <p className="text-2xl font-bold text-foreground">{t('hero.stat4Value')}</p>
          <p className="text-sm text-muted-foreground">{t('hero.stat4')}</p>
        </div>
      </div>
    </div>
  )
}
