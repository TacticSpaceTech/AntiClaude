'use client'

import { useState, useRef, useEffect } from 'react'
import { useI18n, localeNames, localeFlags, type Locale } from '@/lib/i18n'
import { ChevronDown, Check, Globe } from 'lucide-react'

export function LanguageSwitcher() {
  const { locale, setLocale } = useI18n()
  const [isOpen, setIsOpen] = useState(false)
  const dropdownRef = useRef<HTMLDivElement>(null)

  const locales: Locale[] = ['zh', 'en', 'ja', 'ko', 'es']

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-3 py-2 text-sm text-muted-foreground hover:text-foreground transition-colors rounded-lg hover:bg-secondary/50"
      >
        <Globe className="w-4 h-4" />
        <span className="hidden sm:inline">{localeFlags[locale]}</span>
        <ChevronDown className={`w-3 h-3 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
      </button>

      {isOpen && (
        <div className="absolute right-0 mt-2 w-40 bg-card border border-border rounded-lg shadow-xl overflow-hidden z-50">
          {locales.map((l) => (
            <button
              key={l}
              onClick={() => {
                setLocale(l)
                setIsOpen(false)
              }}
              className={`w-full flex items-center justify-between px-4 py-2.5 text-sm hover:bg-secondary/50 transition-colors ${
                locale === l ? 'text-foreground bg-secondary/30' : 'text-muted-foreground'
              }`}
            >
              <span className="flex items-center gap-2">
                <span className="text-xs font-medium opacity-60">{localeFlags[l]}</span>
                <span>{localeNames[l]}</span>
              </span>
              {locale === l && <Check className="w-4 h-4 text-foreground" />}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
