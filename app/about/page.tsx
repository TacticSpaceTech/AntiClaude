import type { Metadata } from 'next'
import Link from 'next/link'
import { I18nWrapper } from '@/components/i18n-wrapper'
import { AboutSection } from '@/components/about-section'
import { FAQSection } from '@/components/faq-section'

export const metadata: Metadata = {
  title: 'About - AntiClaude',
  description: 'Learn about AntiClaude: open-source AI agent security testing, our mission, team, and project stats.',
}

const navLinks = [
  { href: '/#features', label: 'Features' },
  { href: '/docs', label: 'Docs' },
  { href: '/blog', label: 'Blog' },
  { href: '/about', label: 'About', active: true },
]

export default function AboutPage() {
  return (
    <div className="min-h-screen bg-background">
      <header className="border-b border-primary/20 bg-background/90 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-5xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2.5 hover:opacity-80 transition-opacity">
            <img src="/icon-192x192.png" alt="AntiClaude" className="w-8 h-8 rounded" />
            <span className="font-semibold text-primary text-lg font-mono">AntiClaude</span>
          </Link>
          <nav className="flex items-center gap-6">
            {navLinks.map((link) => (
              <Link
                key={link.href}
                href={link.href}
                className={`text-sm font-mono transition-colors ${
                  link.active
                    ? 'text-primary'
                    : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                {link.label}
              </Link>
            ))}
          </nav>
        </div>
      </header>

      <main>
        {/* Hero */}
        <section className="py-20 relative">
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,_rgba(0,255,65,0.04)_0%,_transparent_60%)]" />
          <div className="max-w-5xl mx-auto px-6 relative">
            <p className="text-sm font-mono text-primary/60 mb-3 tracking-wider">// about</p>
            <h1 className="text-4xl md:text-5xl font-mono font-bold text-foreground mb-6">
              About AntiClaude
            </h1>
            <p className="text-muted-foreground leading-relaxed max-w-2xl text-lg">
              Open-source security testing for AI agents. Red-team your LLM-powered
              applications before attackers do.
            </p>
          </div>
        </section>

        {/* Existing AboutSection component */}
        <I18nWrapper>
          <AboutSection />
        </I18nWrapper>

        {/* Our Mission */}
        <section className="py-24 border-t border-primary/10 relative">
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_rgba(0,255,65,0.02)_0%,_transparent_50%)]" />
          <div className="max-w-5xl mx-auto px-6 relative">
            <p className="text-sm font-mono text-primary/60 mb-3 tracking-wider">// mission</p>
            <h2 className="text-3xl md:text-4xl font-mono font-bold text-foreground mb-8">
              Our Mission
            </h2>
            <div className="grid md:grid-cols-2 gap-10">
              <div className="space-y-4 text-muted-foreground leading-relaxed">
                <p>
                  AI agents are being deployed everywhere -- handling customer data,
                  executing code, managing infrastructure. Yet most teams have no way
                  to systematically test these agents for security vulnerabilities.
                </p>
                <p>
                  When Promptfoo was acquired by OpenAI, the ecosystem lost its most
                  prominent independent red-teaming tool. AntiClaude exists to fill
                  that gap: a truly open-source, vendor-neutral security scanner that
                  anyone can run, audit, and extend.
                </p>
              </div>
              <div className="space-y-4 text-muted-foreground leading-relaxed">
                <p>
                  We believe security tooling for AI must remain independent. When
                  testing tools are owned by the same companies building the models,
                  objectivity is compromised. AntiClaude will always be community-driven
                  and transparent.
                </p>
                <p>
                  Our goal is to make AI agent security testing as routine as unit
                  testing -- fast, automated, and integrated into every CI/CD pipeline.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Team & Project Info */}
        <section className="py-24 border-t border-primary/10 relative">
          <div className="max-w-5xl mx-auto px-6 relative">
            <p className="text-sm font-mono text-primary/60 mb-3 tracking-wider">// project</p>
            <h2 className="text-3xl md:text-4xl font-mono font-bold text-foreground mb-8">
              The Project
            </h2>

            <div className="grid md:grid-cols-2 gap-8 mb-12">
              <div className="p-6 rounded-lg bg-card/80 backdrop-blur-sm border border-border">
                <h3 className="text-lg font-semibold text-foreground font-mono mb-3">
                  Built by TacticSpaceTech
                </h3>
                <p className="text-muted-foreground text-sm leading-relaxed">
                  AntiClaude is developed and maintained by TacticSpaceTech, a team
                  focused on building open-source security infrastructure for the
                  AI agent ecosystem.
                </p>
              </div>
              <div className="p-6 rounded-lg bg-card/80 backdrop-blur-sm border border-border">
                <h3 className="text-lg font-semibold text-foreground font-mono mb-3">
                  Open Source (AGPL-3.0)
                </h3>
                <p className="text-muted-foreground text-sm leading-relaxed">
                  Licensed under AGPL-3.0 to ensure the project and all derivatives
                  remain open. Inspect the source, contribute payloads, or fork it
                  for your own needs.
                </p>
              </div>
            </div>

            {/* Key Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {[
                { value: '64', label: 'Attack Payloads' },
                { value: '7', label: 'OWASP Categories' },
                { value: '61', label: 'Tests Passing' },
                { value: 'v1.0.0', label: 'Published on npm' },
              ].map((stat, index) => (
                <div
                  key={index}
                  className="p-5 rounded-lg bg-card/80 backdrop-blur-sm border border-border text-center group hover:border-primary/40 transition-all"
                >
                  <p className="text-3xl font-bold text-primary font-mono mb-1 drop-shadow-[0_0_10px_rgba(0,255,65,0.3)] group-hover:drop-shadow-[0_0_15px_rgba(0,255,65,0.5)] transition-all">
                    {stat.value}
                  </p>
                  <p className="text-xs text-muted-foreground">{stat.label}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Existing FAQSection component */}
        <I18nWrapper>
          <FAQSection />
        </I18nWrapper>

        {/* Footer CTA */}
        <section className="py-24 border-t border-primary/10 relative">
          <div className="max-w-5xl mx-auto px-6 text-center relative">
            <p className="text-sm font-mono text-primary/60 mb-3 tracking-wider">// contribute</p>
            <h2 className="text-3xl md:text-4xl font-mono font-bold text-foreground mb-4">
              Join the Project
            </h2>
            <p className="text-muted-foreground leading-relaxed max-w-xl mx-auto mb-8">
              AntiClaude is open source. Star the repo, open an issue, submit a payload,
              or just try it on your agents.
            </p>
            <a
              href="https://github.com/TacticSpaceTech/AntiClaude"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 bg-primary text-primary-foreground font-mono font-semibold px-6 py-3 rounded-lg hover:bg-primary/90 transition-colors"
            >
              View on GitHub
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
              </svg>
            </a>
          </div>
        </section>
      </main>
    </div>
  )
}
