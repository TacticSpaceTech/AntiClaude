'use client'

import Link from 'next/link'
import { useState } from 'react'
import { I18nProvider, useI18n } from '@/lib/i18n'
import { LanguageSwitcher } from './language-switcher'
import { Github, Menu, X } from 'lucide-react'

const NAV_LINKS = [
  { href: '/features', key: 'nav.features' },
  { href: '/docs', key: 'nav.docs' },
  { href: '/blog', key: 'nav.blog' },
  { href: '/about', key: 'nav.about' },
]

function HeaderInner({ active }: { active?: string }) {
  const { t } = useI18n()
  const [mobileOpen, setMobileOpen] = useState(false)

  return (
    <header className="border-b border-border bg-background/90 backdrop-blur-md sticky top-0 z-50">
      <div className="max-w-5xl mx-auto px-6 h-16 flex items-center justify-between">
        <Link href="/" className="flex items-center gap-2.5 hover:opacity-80 transition-opacity">
          <img src="/icon-192x192.png" alt="AntiClaude" className="w-8 h-8 rounded" />
          <span className="font-semibold text-primary text-lg font-mono">AntiClaude</span>
        </Link>

        {/* Desktop Nav */}
        <nav className="hidden md:flex items-center gap-6">
          {NAV_LINKS.map(link => (
            <Link
              key={link.href}
              href={link.href}
              className={`text-sm font-mono transition-colors ${
                active === link.href ? 'text-primary' : 'text-muted-foreground hover:text-primary'
              }`}
            >
              {t(link.key as any)}
            </Link>
          ))}
        </nav>

        <div className="hidden md:flex items-center gap-3">
          <LanguageSwitcher />
          <a href="https://github.com/TacticSpaceTech/AntiClaude" target="_blank" rel="noopener noreferrer"
             className="text-muted-foreground hover:text-foreground transition-colors">
            <Github className="w-5 h-5" />
          </a>
        </div>

        {/* Mobile toggle */}
        <button className="md:hidden text-muted-foreground" onClick={() => setMobileOpen(!mobileOpen)}>
          {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
        </button>
      </div>

      {/* Mobile Menu */}
      {mobileOpen && (
        <div className="md:hidden border-t border-border bg-background py-4 px-6 space-y-3">
          {NAV_LINKS.map(link => (
            <Link key={link.href} href={link.href}
              className={`block text-sm font-mono ${active === link.href ? 'text-primary' : 'text-muted-foreground hover:text-primary'}`}>
              {t(link.key as any)}
            </Link>
          ))}
          <div className="pt-2 flex items-center gap-3">
            <LanguageSwitcher />
          </div>
        </div>
      )}
    </header>
  )
}

export function SubPageHeader({ active }: { active?: string }) {
  return (
    <I18nProvider>
      <HeaderInner active={active} />
    </I18nProvider>
  )
}
