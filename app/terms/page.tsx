import type { Metadata } from 'next'
import Link from 'next/link'

export const metadata: Metadata = {
  title: 'Terms of Service - AntiClaude',
  description: 'AntiClaude terms of service. Rules and guidelines for using the AntiClaude security tool.',
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

export default function TermsPage() {
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
          <h1 className="text-4xl font-mono font-bold text-foreground mb-2">Terms of Service</h1>
          <p className="text-sm text-muted-foreground font-mono">Effective date: March 17, 2026</p>
        </div>

        <Section title="Acceptance of Terms">
          <p>
            By accessing or using AntiClaude (the &quot;Service&quot;), including the website at anticlaude.dev,
            the CLI tool, and the engine library, you agree to be bound by these Terms of Service
            (&quot;Terms&quot;). If you do not agree to these Terms, do not use the Service.
          </p>
        </Section>

        <Section title="Description of Service">
          <p>
            AntiClaude is an open-source AI agent security red-teaming toolkit. It provides attack
            payloads, an LLM-based judge for leak detection, an MCP configuration scanner, and related
            tools for testing the security posture of AI agent deployments.
          </p>
          <p>
            The Service is provided as a security testing tool intended for authorized use only.
          </p>
        </Section>

        <Section title="License">
          <p>
            AntiClaude is licensed under the{' '}
            <a
              href="https://www.gnu.org/licenses/agpl-3.0.html"
              target="_blank"
              rel="noopener noreferrer"
              className="text-primary hover:underline"
            >
              GNU Affero General Public License v3.0
            </a>{' '}
            (AGPL-3.0). You may use, modify, and distribute the software in accordance with the terms
            of that license. Any derivative works or network-accessible modifications must also be made
            available under the same license.
          </p>
        </Section>

        <Section title="Responsible Use">
          <p className="font-semibold text-foreground">
            You must only use AntiClaude to test endpoints, systems, and configurations that you own
            or have explicit written authorization to test.
          </p>
          <p>
            Unauthorized security testing is illegal in most jurisdictions. By using AntiClaude, you
            acknowledge and agree that:
          </p>
          <ul className="list-disc list-inside space-y-1 ml-2">
            <li>You will only scan endpoints you own or are authorized to test</li>
            <li>You will comply with all applicable local, state, national, and international laws</li>
            <li>You will not use the tool to attack, disrupt, or damage systems without authorization</li>
            <li>You are solely responsible for any consequences of your use of the tool</li>
          </ul>
          <p>
            We reserve the right to restrict access to the web-based scanner for any user who violates
            these terms.
          </p>
        </Section>

        <Section title="Disclaimer of Warranties">
          <p>
            The Service is provided &quot;as is&quot; and &quot;as available&quot; without warranties of any kind,
            either express or implied, including but not limited to implied warranties of merchantability,
            fitness for a particular purpose, and non-infringement.
          </p>
          <p>
            We do not warrant that the Service will be uninterrupted, error-free, or completely secure.
            Security testing results are indicative, not exhaustive. A passing score does not guarantee
            that your agent is free from all vulnerabilities.
          </p>
        </Section>

        <Section title="Limitation of Liability">
          <p>
            To the maximum extent permitted by applicable law, in no event shall AntiClaude, its
            contributors, or its maintainers be liable for any indirect, incidental, special,
            consequential, or punitive damages, or any loss of profits or revenues, whether incurred
            directly or indirectly, or any loss of data, use, goodwill, or other intangible losses,
            resulting from:
          </p>
          <ul className="list-disc list-inside space-y-1 ml-2">
            <li>Your use or inability to use the Service</li>
            <li>Any unauthorized access to or use of our servers or any personal information stored therein</li>
            <li>Any results or lack of results from security scans performed using the Service</li>
            <li>Any third-party actions taken based on scan results</li>
          </ul>
        </Section>

        <Section title="Changes to These Terms">
          <p>
            We reserve the right to modify these Terms at any time. Changes will be posted on this page
            with an updated effective date. Your continued use of the Service after any changes constitutes
            acceptance of the new Terms.
          </p>
        </Section>

        <Section title="Contact">
          <p>
            If you have questions about these Terms, please reach out via{' '}
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
