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
    <section className="py-24 border-t border-border">
      <div className="max-w-3xl mx-auto px-6">
        <div className="text-center mb-16">
          <p className="text-sm font-medium text-muted-foreground mb-3 tracking-wide uppercase">
            {t('faq.label')}
          </p>
          <h2 className="text-3xl md:text-4xl font-bold text-foreground mb-4 text-balance">
            {t('faq.title')}
          </h2>
        </div>
        
        <div className="space-y-3">
          {faqs.map((faq, index) => (
            <div 
              key={index}
              className="border border-border rounded-xl overflow-hidden"
            >
              <button
                onClick={() => setOpenIndex(openIndex === index ? null : index)}
                className="w-full p-5 text-left flex items-center justify-between gap-4 bg-card hover:bg-card/80 transition-colors"
              >
                <span className="font-medium text-foreground">
                  {t(faq.qKey)}
                </span>
                <ChevronDown 
                  className={cn(
                    "w-5 h-5 text-muted-foreground shrink-0 transition-transform",
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
                  <p className="p-5 pt-0 text-sm text-muted-foreground leading-relaxed">
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
