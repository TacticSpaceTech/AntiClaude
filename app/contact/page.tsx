import type { Metadata } from 'next'
import { SubPageHeader } from '@/components/sub-page-header'

export const metadata: Metadata = {
  title: 'Contact - AntiClaude',
  description: 'Get in touch with the AntiClaude team. Report issues, ask questions, or discuss AI agent security.',
}

export default function ContactPage() {
  return (
    <div className="min-h-screen bg-background">
      <SubPageHeader active="/contact" />

      <main className="max-w-4xl mx-auto px-6 py-12 pb-24">
        <div className="mb-12">
          <p className="text-sm font-mono text-primary/60 mb-2">// contact</p>
          <h1 className="text-4xl font-mono font-bold text-foreground mb-4">Get in Touch</h1>
          <p className="text-muted-foreground leading-relaxed max-w-2xl">
            AntiClaude is an open-source project. The best way to reach us is through GitHub.
          </p>
        </div>

        <div className="grid gap-6 md:grid-cols-2">
          <a
            href="https://github.com/TacticSpaceTech/AntiClaude/issues"
            target="_blank"
            rel="noopener noreferrer"
            className="group bg-card/80 border border-border rounded-lg p-6 hover:border-primary/40 transition-colors"
          >
            <div className="flex items-center gap-3 mb-3">
              <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                <svg className="w-5 h-5 text-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-9 3.75h.008v.008H12v-.008Z" />
                </svg>
              </div>
              <h2 className="text-lg font-mono font-semibold text-foreground group-hover:text-primary transition-colors">
                GitHub Issues
              </h2>
            </div>
            <p className="text-sm text-muted-foreground leading-relaxed">
              Report bugs, request features, or ask technical questions. This is the fastest way to
              get a response from the maintainers.
            </p>
            <p className="text-xs font-mono text-primary/60 mt-3">
              github.com/TacticSpaceTech/AntiClaude/issues
            </p>
          </a>

          <a
            href="https://github.com/TacticSpaceTech/AntiClaude/discussions"
            target="_blank"
            rel="noopener noreferrer"
            className="group bg-card/80 border border-border rounded-lg p-6 hover:border-primary/40 transition-colors"
          >
            <div className="flex items-center gap-3 mb-3">
              <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                <svg className="w-5 h-5 text-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M20.25 8.511c.884.284 1.5 1.128 1.5 2.097v4.286c0 1.136-.847 2.1-1.98 2.193-.34.027-.68.052-1.02.072v3.091l-3-3c-1.354 0-2.694-.055-4.02-.163a2.115 2.115 0 0 1-.825-.242m9.345-8.334a2.126 2.126 0 0 0-.476-.095 48.64 48.64 0 0 0-8.048 0c-1.131.094-1.976 1.057-1.976 2.192v4.286c0 .837.46 1.58 1.155 1.951m9.345-8.334V6.637c0-1.621-1.152-3.026-2.76-3.235A48.455 48.455 0 0 0 11.25 3c-2.115 0-4.198.137-6.24.402-1.608.209-2.76 1.614-2.76 3.235v6.226c0 1.621 1.152 3.026 2.76 3.235.577.075 1.157.14 1.74.194V21l4.155-4.155" />
                </svg>
              </div>
              <h2 className="text-lg font-mono font-semibold text-foreground group-hover:text-primary transition-colors">
                GitHub Discussions
              </h2>
            </div>
            <p className="text-sm text-muted-foreground leading-relaxed">
              Join the community. Discuss AI agent security, share your findings, suggest new attack
              categories, or ask for help with your setup.
            </p>
            <p className="text-xs font-mono text-primary/60 mt-3">
              github.com/TacticSpaceTech/AntiClaude/discussions
            </p>
          </a>

          <div className="bg-card/80 border border-border rounded-lg p-6">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                <svg className="w-5 h-5 text-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 1 0-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H6.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z" />
                </svg>
              </div>
              <h2 className="text-lg font-mono font-semibold text-foreground">
                Security Reports
              </h2>
            </div>
            <p className="text-sm text-muted-foreground leading-relaxed">
              If you discover a security vulnerability in AntiClaude itself, please report it
              responsibly via GitHub Issues with the &quot;security&quot; label, or email us directly.
            </p>
            <p className="text-xs font-mono text-primary/60 mt-3">
              security@anticlaude.dev
            </p>
          </div>

          <div className="bg-card/80 border border-border rounded-lg p-6">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                <svg className="w-5 h-5 text-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M17.25 6.75 22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3-4.5 16.5" />
                </svg>
              </div>
              <h2 className="text-lg font-mono font-semibold text-foreground">
                Contributing
              </h2>
            </div>
            <p className="text-sm text-muted-foreground leading-relaxed">
              Want to contribute new payloads, improve the engine, or fix bugs? Check out
              the contributing guide and open a pull request.
            </p>
            <p className="text-xs font-mono text-primary/60 mt-3">
              <a
                href="https://github.com/TacticSpaceTech/AntiClaude/blob/main/CONTRIBUTING.md"
                target="_blank"
                rel="noopener noreferrer"
                className="hover:text-primary transition-colors"
              >
                CONTRIBUTING.md
              </a>
            </p>
          </div>
        </div>
      </main>
    </div>
  )
}
