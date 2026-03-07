'use client'

import { useI18n } from '@/lib/i18n'
import { ArrowRight } from 'lucide-react'

interface CTASectionProps {
  onStartTest?: () => void
}

export function CTASection({ onStartTest }: CTASectionProps) {
  const { t } = useI18n()
  
  const handleClick = () => {
    if (onStartTest) {
      onStartTest()
    } else {
      window.scrollTo({ top: 0, behavior: 'smooth' })
    }
  }
  
  return (
    <section className="py-24 border-t border-border bg-card/50">
      <div className="max-w-3xl mx-auto px-6 text-center">
        <h2 className="text-3xl md:text-4xl font-bold text-foreground mb-4 text-balance">
          {t('cta.title')}
        </h2>
        <p className="text-lg text-muted-foreground mb-8 max-w-xl mx-auto text-pretty">
          {t('cta.subtitle')}
        </p>
        <button
          onClick={handleClick}
          className="inline-flex items-center gap-2 px-6 py-3 bg-foreground text-background font-medium rounded-lg hover:bg-foreground/90 transition-colors"
        >
          {t('cta.button')}
          <ArrowRight className="w-4 h-4" />
        </button>
        <p className="mt-6 text-xs text-muted-foreground">
          {t('cta.note')}
        </p>
      </div>
    </section>
  )
}
