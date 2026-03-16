import type { Metadata } from 'next'
import Link from 'next/link'
import { I18nWrapper } from '@/components/i18n-wrapper'
import { FeaturesSection } from '@/components/features-section'
import { HowItWorksSection } from '@/components/how-it-works-section'
import { AttackVectorsSection } from '@/components/attack-vectors-section'

export const metadata: Metadata = {
  title: 'Features — AntiClaude',
  description: 'Explore AntiClaude features: attack vectors, security scanning engine, LLM judge, and CI/CD integration for AI agent red-teaming.',
}

export default function FeaturesPage() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="border-b border-border bg-background/90 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-5xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2.5 hover:opacity-80 transition-opacity">
            <img src="/icon-192x192.png" alt="AntiClaude" className="w-8 h-8 rounded" />
            <span className="font-semibold text-primary text-lg font-mono">AntiClaude</span>
          </Link>
          <nav className="flex items-center gap-6 text-sm font-mono text-muted-foreground">
            <Link href="/features" className="text-primary">Features</Link>
            <Link href="/docs" className="hover:text-primary transition-colors">Docs</Link>
            <Link href="/blog" className="hover:text-primary transition-colors">Blog</Link>
            <Link href="/cicd" className="hover:text-primary transition-colors">CI/CD</Link>
          </nav>
        </div>
      </header>

      <I18nWrapper>
        <FeaturesSection />
        <HowItWorksSection />
        <AttackVectorsSection />
      </I18nWrapper>

      <section className="border-t border-border py-20">
        <div className="max-w-5xl mx-auto px-6 text-center">
          <p className="text-sm font-mono text-primary/60 mb-3">// ready to start?</p>
          <h2 className="text-3xl font-mono font-bold text-foreground mb-4">
            Secure your AI agents today
          </h2>
          <p className="text-muted-foreground mb-8 max-w-xl mx-auto">
            Run your first scan in under a minute. No account required.
          </p>
          <div className="flex items-center justify-center gap-4">
            <Link
              href="/"
              className="px-6 py-3 bg-primary text-primary-foreground font-mono text-sm font-medium rounded-lg hover:bg-primary/90 transition-colors"
            >
              Start a scan
            </Link>
            <Link
              href="/docs"
              className="px-6 py-3 border border-border text-muted-foreground font-mono text-sm font-medium rounded-lg hover:text-foreground hover:border-foreground/30 transition-colors"
            >
              Read the docs
            </Link>
          </div>
        </div>
      </section>
    </div>
  )
}
