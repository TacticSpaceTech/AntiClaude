'use client'

import { useState } from 'react'
import { useI18n } from '@/lib/i18n'
import { ChevronDown } from 'lucide-react'
import { cn } from '@/lib/utils'

export function FAQSection() {
  const { t } = useI18n()
  const [openIndex, setOpenIndex] = useState<number | null>(0)
  
  const faqs = [
    { qKey: 'faq.q1' as const, aKey: 'faq.a1' as const },
    { qKey: 'faq.q2' as const, aKey: 'faq.a2' as const },
    { qKey: 'faq.q3' as const, aKey: 'faq.a3' as const },
    { qKey: 'faq.q4' as const, aKey: 'faq.a4' as const },
    { qKey: 'faq.q5' as const, aKey: 'faq.a5' as const },
    { qKey: 'faq.q6' as const, aKey: 'faq.a6' as const },
  ]
  
  return (
    <section className="py-24 border-t border-primary/10 relative">
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,_rgba(0,255,65,0.03)_0%,_transparent_50%)]" />
      
      <div className="max-w-3xl mx-auto px-6 relative">
        <div className="text-center mb-16">
          <p className="text-sm font-mono text-primary/60 mb-3 tracking-wider">
            {'// '}{t('faq.label')}
          </p>
          <h2 className="text-3xl md:text-4xl font-bold text-foreground mb-4 text-balance">
            {t('faq.title')}
          </h2>
        </div>
        
        <div className="space-y-3">
          {faqs.map((faq, index) => (
            <div 
              key={index}
              className="border border-primary/20 rounded-lg overflow-hidden bg-black/40 backdrop-blur-sm hover:border-primary/30 transition-colors"
            >
              <button
                onClick={() => setOpenIndex(openIndex === index ? null : index)}
                className="w-full p-5 text-left flex items-center justify-between gap-4 hover:bg-primary/5 transition-colors"
              >
                <span className="font-medium text-foreground font-mono text-sm">
                  <span className="text-primary/50 mr-2">[{String(index).padStart(2, '0')}]</span>
                  {t(faq.qKey)}
                </span>
                <ChevronDown 
                  className={cn(
                    "w-5 h-5 text-primary/50 shrink-0 transition-transform",
                    openIndex === index && "rotate-180"
                  )}
                />
              </button>
              <div 
                className={cn(
                  "grid transition-all duration-200",
                  openIndex === index ? "grid-rows-[1fr]" : "grid-rows-[0fr]"
                )}
              >
                <div className="overflow-hidden">
                  <p className="p-5 pt-0 text-sm text-muted-foreground leading-relaxed border-t border-primary/10">
                    {t(faq.aKey)}
                  </p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
