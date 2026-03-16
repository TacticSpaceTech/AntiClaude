import type { Metadata } from 'next'
import Link from 'next/link'

export const metadata: Metadata = {
  title: 'Privacy Policy - AntiClaude',
  description: 'AntiClaude privacy policy. How we handle your data when you use the AntiClaude security scanner.',
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mb-10">
      <h2 className="text-xl font-mono font-semibold text-foreground mb-3">
        <span className="text-primary/50">## </span>{title}
      </h2>
      <div className="text-muted-foreground leading-relaxed space-y-3">{children}</div>
    </section>
  )
}

export default function PrivacyPage() {
  return (
    <div className="min-h-screen bg-background">
      <header className="border-b border-primary/20 bg-background/90 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-4xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2.5 hover:opacity-80 transition-opacity">
            <img src="/icon-192x192.png" alt="AntiClaude" className="w-8 h-8 rounded" />
            <span className="font-semibold text-primary text-lg font-mono">AntiClaude</span>
          </Link>
          <Link href="/" className="text-sm text-muted-foreground hover:text-foreground transition-colors font-mono">
            &larr; Home
          </Link>
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-6 py-12 pb-24">
        <div className="mb-10">
          <p className="text-sm font-mono text-primary/60 mb-2">// legal</p>
          <h1 className="text-4xl font-mono font-bold text-foreground mb-2">Privacy Policy</h1>
          <p className="text-sm text-muted-foreground font-mono">Effective date: March 17, 2026</p>
        </div>

        <Section title="Introduction">
          <p>
            AntiClaude (&quot;we&quot;, &quot;us&quot;, &quot;our&quot;) is an open-source AI agent security
            red-teaming tool. This Privacy Policy explains how we collect, use, and protect information
            when you use the AntiClaude website (anticlaude.dev) and CLI tool.
          </p>
        </Section>

        <Section title="Information Collection">
          <p>
            <strong className="text-foreground">CLI Tool:</strong> The AntiClaude CLI runs entirely on your
            local machine. We do not collect, transmit, or store any data from CLI scans. Your endpoint URLs,
            authentication tokens, scan results, and security reports never leave your environment.
          </p>
          <p>
            <strong className="text-foreground">Web Scanner:</strong> When you use the web-based scanner at
            anticlaude.dev, scan requests are processed through our server to reach your specified endpoint.
            We do not log or store the endpoint URLs, authentication headers, payloads sent, or responses received.
          </p>
          <p>
            <strong className="text-foreground">Email (optional):</strong> If you voluntarily provide your email
            address to unlock a full report, we store that email address solely for the purpose of delivering
            the report and occasional product updates. You may unsubscribe at any time.
          </p>
        </Section>

        <Section title="Usage Data">
          <p>
            We use Vercel Analytics to collect anonymous, aggregated website traffic data. This includes
            page views, referral sources, country-level geolocation, browser type, and device type.
            No personally identifiable information is collected through analytics.
          </p>
        </Section>

        <Section title="Cookies">
          <p>
            The AntiClaude website uses only essential cookies required for basic functionality (such as
            language preference). We do not use advertising cookies, tracking pixels, or third-party
            marketing cookies.
          </p>
        </Section>

        <Section title="Third-Party Services">
          <p>
            We use the following third-party services:
          </p>
          <ul className="list-disc list-inside space-y-1 ml-2">
            <li><strong className="text-foreground">Vercel</strong> &mdash; website hosting and analytics</li>
            <li><strong className="text-foreground">GitHub</strong> &mdash; source code hosting and issue tracking</li>
            <li><strong className="text-foreground">npm</strong> &mdash; package distribution</li>
          </ul>
          <p>
            Each of these services has its own privacy policy governing how they handle data.
          </p>
        </Section>

        <Section title="Data Security">
          <p>
            We take reasonable measures to protect any information we do collect. The website is served
            over HTTPS. The CLI tool operates entirely locally. We do not store scan results on any server.
          </p>
        </Section>

        <Section title="Changes to This Policy">
          <p>
            We may update this Privacy Policy from time to time. Changes will be posted on this page with
            an updated effective date. Continued use of the service after changes constitutes acceptance of
            the revised policy.
          </p>
        </Section>

        <Section title="Contact">
          <p>
            If you have questions about this Privacy Policy, please reach out via{' '}
            <a
              href="https://github.com/TacticSpaceTech/AntiClaude/issues"
              target="_blank"
              rel="noopener noreferrer"
              className="text-primary hover:underline"
            >
              GitHub Issues
            </a>
            .
          </p>
        </Section>
      </main>
    </div>
  )
}
