import type { Metadata } from 'next'
import Link from 'next/link'
import { SubPageHeader } from '@/components/sub-page-header'
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
      <SubPageHeader active="/features" />

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
