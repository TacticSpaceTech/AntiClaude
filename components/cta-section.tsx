'use client'

import { useI18n } from '@/lib/i18n'
import { Zap } from 'lucide-react'

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
    <section className="py-24 border-t border-primary/10 relative overflow-hidden">
      {/* Matrix-style background */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_rgba(0,255,65,0.08)_0%,_transparent_60%)]" />
      <div className="absolute inset-0 bg-[linear-gradient(to_bottom,transparent,rgba(0,0,0,0.5))]" />
      
      <div className="max-w-3xl mx-auto px-6 text-center relative">
        <div className="inline-flex items-center gap-2 px-3 py-1 mb-6 text-xs font-mono rounded border border-primary/30 bg-primary/5 text-primary">
          <span className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
          SYSTEM_READY
        </div>
        
        <h2 className="text-3xl md:text-4xl font-bold text-foreground mb-4 text-balance">
          {t('cta.title')}
        </h2>
        <p className="text-lg text-muted-foreground mb-8 max-w-xl mx-auto text-pretty">
          {t('cta.subtitle')}
        </p>
        
        <button
          onClick={handleClick}
          className="inline-flex items-center gap-2 px-8 py-4 bg-primary text-primary-foreground font-mono font-bold rounded-lg hover:bg-primary/90 transition-all shadow-[0_0_30px_rgba(0,255,65,0.4)] hover:shadow-[0_0_40px_rgba(0,255,65,0.6)]"
        >
          <Zap className="w-5 h-5" />
          {t('cta.button')}
        </button>
        
        <p className="mt-8 text-xs text-primary/40 font-mono">
          {'// '}{t('cta.note')}
        </p>
      </div>
    </section>
  )
}
