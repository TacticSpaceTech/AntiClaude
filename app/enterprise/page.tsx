import type { Metadata } from 'next'
import Link from 'next/link'
import { SubPageHeader } from '@/components/sub-page-header'

export const metadata: Metadata = {
  title: 'Enterprise - AntiClaude',
  description: 'Enterprise-grade AI agent security: team collaboration, compliance reporting, CI/CD integration, and priority support.',
}

const tiers = [
  {
    name: 'Community',
    price: 'Free',
    description: 'Everything you need to get started with AI agent security testing.',
    comingSoon: false,
    features: [
      'Full CLI with all commands',
      '64 attack payloads across 7 OWASP categories',
      'Open-source engine and payloads',
      'Local HTML and JSON reports',
      'MCP server configuration audit',
      'GitHub Action integration',
    ],
  },
  {
    name: 'Pro',
    price: '$19/mo',
    description: 'Cloud-powered insights and historical tracking for individual developers.',
    comingSoon: true,
    features: [
      'Everything in Community',
      'Cloud report dashboard',
      'Historical security score trends',
      'Team report sharing via links',
      'Priority payload updates',
      'Email support',
    ],
  },
  {
    name: 'Team',
    price: '$49/mo per seat',
    description: 'Built for teams shipping AI agents in production with compliance needs.',
    comingSoon: true,
    features: [
      'Everything in Pro',
      'Deep CI/CD integration (GitHub, GitLab, Jenkins)',
      'Role-based access control (RBAC)',
      'Compliance report export (PDF, CSV)',
      'SOC 2 / ISO 27001 compatible reports',
      'SLA with dedicated support channel',
    ],
  },
]

const enterpriseReasons = [
  {
    title: 'Centralized Vulnerability Tracking',
    description: 'Track security scores across all your agents in one dashboard. Spot regressions before they reach production.',
  },
  {
    title: 'Compliance-Ready Reports',
    description: 'Generate audit-ready reports compatible with SOC 2 and ISO 27001 frameworks. Export to PDF or CSV for compliance teams.',
  },
  {
    title: 'Priority Payload Access',
    description: 'Get early access to new OWASP categories and attack payloads as the threat landscape evolves.',
  },
  {
    title: 'Dedicated Support',
    description: 'Priority support channel with guaranteed response times. Get help configuring scans, interpreting results, and hardening your agents.',
  },
]

export default function EnterprisePage() {
  return (
    <div className="min-h-screen bg-background">
      <SubPageHeader active="/enterprise" />

      <main>
        {/* Hero */}
        <section className="py-24 relative">
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,_rgba(0,255,65,0.04)_0%,_transparent_60%)]" />
          <div className="max-w-5xl mx-auto px-6 relative text-center">
            <p className="text-sm font-mono text-primary/60 mb-3 tracking-wider">// enterprise</p>
            <h1 className="text-4xl md:text-5xl font-mono font-bold text-foreground mb-6">
              Enterprise-Grade AI Agent Security
            </h1>
            <p className="text-muted-foreground leading-relaxed max-w-2xl mx-auto text-lg">
              Everything in the open-source CLI, plus team collaboration, compliance
              reporting, and priority support.
            </p>
          </div>
        </section>

        {/* Tiers */}
        <section className="py-24 border-t border-primary/10 relative">
          <div className="max-w-5xl mx-auto px-6 relative">
            <p className="text-sm font-mono text-primary/60 mb-3 tracking-wider">// plans</p>
            <h2 className="text-3xl md:text-4xl font-mono font-bold text-foreground mb-12">
              {"What's Included"}
            </h2>

            <div className="grid md:grid-cols-3 gap-6">
              {tiers.map((tier) => (
                <div
                  key={tier.name}
                  className="p-6 rounded-lg bg-card/80 backdrop-blur-sm border border-border hover:border-primary/40 transition-all flex flex-col"
                >
                  <div className="flex items-center gap-3 mb-2">
                    <h3 className="text-xl font-semibold text-foreground font-mono">
                      {tier.name}
                    </h3>
                    {tier.comingSoon && (
                      <span className="text-xs bg-primary/10 text-primary/60 px-2 py-0.5 rounded font-mono">
                        Coming Soon
                      </span>
                    )}
                  </div>
                  <p className="text-2xl font-bold text-primary font-mono mb-3">
                    {tier.price}
                  </p>
                  <p className="text-sm text-muted-foreground leading-relaxed mb-6">
                    {tier.description}
                  </p>
                  <ul className="space-y-3 mt-auto">
                    {tier.features.map((feature, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm text-muted-foreground">
                        <span className="text-primary/60 font-mono mt-0.5 shrink-0">+</span>
                        {feature}
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Why Enterprise */}
        <section className="py-24 border-t border-primary/10 relative">
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_bottom_left,_rgba(0,255,65,0.03)_0%,_transparent_50%)]" />
          <div className="max-w-5xl mx-auto px-6 relative">
            <p className="text-sm font-mono text-primary/60 mb-3 tracking-wider">// why enterprise</p>
            <h2 className="text-3xl md:text-4xl font-mono font-bold text-foreground mb-12">
              Why Enterprise?
            </h2>

            <div className="grid md:grid-cols-2 gap-6">
              {enterpriseReasons.map((reason, index) => (
                <div
                  key={index}
                  className="p-6 rounded-lg bg-card/80 backdrop-blur-sm border border-border"
                >
                  <div className="flex items-center gap-2 mb-3">
                    <span className="text-primary/50 font-mono text-sm">
                      [{String(index + 1).padStart(2, '0')}]
                    </span>
                    <h3 className="text-lg font-semibold text-foreground font-mono">
                      {reason.title}
                    </h3>
                  </div>
                  <p className="text-sm text-muted-foreground leading-relaxed">
                    {reason.description}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Get Started */}
        <section className="py-24 border-t border-primary/10 relative">
          <div className="max-w-5xl mx-auto px-6 text-center relative">
            <p className="text-sm font-mono text-primary/60 mb-3 tracking-wider">// get started</p>
            <h2 className="text-3xl md:text-4xl font-mono font-bold text-foreground mb-4">
              Get Started
            </h2>
            <p className="text-muted-foreground leading-relaxed max-w-xl mx-auto mb-10">
              Start testing your AI agents for free today, or reach out to discuss
              enterprise needs.
            </p>

            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <Link
                href="/"
                className="inline-flex items-center gap-2 bg-primary text-primary-foreground font-mono font-semibold px-6 py-3 rounded-lg hover:bg-primary/90 transition-colors"
              >
                Start with the Free CLI
              </Link>
              <Link
                href="/contact"
                className="inline-flex items-center gap-2 border border-border text-foreground font-mono font-semibold px-6 py-3 rounded-lg hover:border-primary/40 hover:bg-card/80 transition-colors"
              >
                Contact Us for Enterprise
              </Link>
              <a
                href="https://github.com/TacticSpaceTech/AntiClaude"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-2 text-sm font-mono text-muted-foreground hover:text-primary transition-colors"
              >
                GitHub
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                </svg>
              </a>
            </div>
          </div>
        </section>
      </main>
    </div>
  )
}
