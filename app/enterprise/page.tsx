import type { Metadata } from 'next'
import Link from 'next/link'
import { SubPageHeader } from '@/components/sub-page-header'

export const metadata: Metadata = {
  title: 'Roadmap - AntiClaude',
  description: 'Planned team workflows for AntiClaude reports, history, and CI visibility.',
}

const tiers = [
  {
    name: 'Community',
    status: 'Shipped',
    description: 'Everything currently available in the open-source local workflow.',
    comingSoon: false,
    features: [
      'Full CLI with all commands',
      '64 attack payloads across 7 OWASP categories',
      'Open-source engine and payloads',
      'Local HTML and JSON reports',
      'Local runtime control beta examples',
      'Guard SDK and local guard alpha',
      'Support-agent runtime policy and review queue',
      'MCP server configuration audit',
      'GitHub Action integration',
    ],
  },
  {
    name: 'Individual Cloud History',
    status: 'Planned',
    description: 'Planned cloud report history for individual developers.',
    comingSoon: true,
    features: [
      'Everything in Community',
      'Report history views',
      'Security score trend views',
      'Report sharing links',
      'Priority payload updates',
      'Email support',
    ],
  },
  {
    name: 'Team Workflows',
    status: 'Planned',
    description: 'Planned team workflows for organizations running repeated evals.',
    comingSoon: true,
    features: [
      'Everything in Pro',
      'CI run history across repositories',
      'Role-based access control (RBAC)',
      'Shared report review queues',
      'Baseline drift views',
      'Dedicated setup support',
    ],
  },
]

const enterpriseReasons = [
  {
    title: 'Local Regression Evidence First',
    description: 'Compare baseline and current reports locally before a future hosted workflow exists.',
  },
  {
    title: 'Evidence-First Reports',
    description: 'Review raw request and response evidence, detector indicators, remediation guidance, and reproduction commands from each scan.',
  },
  {
    title: 'Policy And Replay Foundation',
    description: 'Use the shipped Guard SDK, runtime policy, review queue, and trace replay to shape future workflows.',
  },
  {
    title: 'Roadmap Input',
    description: 'Discuss repeated eval needs, CI gates, and report review workflows without implying a current paid dashboard.',
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
            <p className="text-sm font-mono text-primary/60 mb-3 tracking-wider">// roadmap</p>
            <h1 className="text-4xl md:text-5xl font-mono font-bold text-foreground mb-6">
              Roadmap for Agent Security Workflows
            </h1>
            <p className="text-muted-foreground leading-relaxed max-w-2xl mx-auto text-lg">
              The shipped product is the open-source CLI, engine, web scanner, local runtime control beta examples, Guard alpha, and GitHub Action.
              Team dashboards and cloud report history are planned, not available yet.
            </p>
          </div>
        </section>

        {/* Tiers */}
        <section className="py-24 border-t border-primary/10 relative">
          <div className="max-w-5xl mx-auto px-6 relative">
            <p className="text-sm font-mono text-primary/60 mb-3 tracking-wider">// current and planned</p>
            <h2 className="text-3xl md:text-4xl font-mono font-bold text-foreground mb-12">
              Scope
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
                    {tier.status}
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

        {/* Why Team Workflows */}
        <section className="py-24 border-t border-primary/10 relative">
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_bottom_left,_rgba(0,255,65,0.03)_0%,_transparent_50%)]" />
          <div className="max-w-5xl mx-auto px-6 relative">
            <p className="text-sm font-mono text-primary/60 mb-3 tracking-wider">// why team workflows</p>
            <h2 className="text-3xl md:text-4xl font-mono font-bold text-foreground mb-12">
              Why Team Workflows?
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
              Start with the local workflow today, or reach out to discuss roadmap needs.
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
                Discuss Roadmap Needs
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
