'use client'

export function HeroSection() {
  return (
    <div className="text-center mb-16">
      {/* Badge */}
      <div className="inline-flex items-center gap-2 px-3 py-1.5 mb-8 text-xs font-medium rounded-full bg-secondary border border-border text-muted-foreground">
        <span className="w-1.5 h-1.5 rounded-full bg-success animate-pulse" />
        LLM Security Testing Platform
      </div>

      {/* Main Headline */}
      <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold text-foreground mb-6 leading-tight tracking-tight text-balance">
        Is your AI Agent
        <br />
        <span className="text-accent">bulletproof?</span>
      </h1>

      {/* Subtitle */}
      <p className="text-lg text-muted-foreground max-w-xl mx-auto mb-10 leading-relaxed text-pretty">
        Automated penetration testing for LLM applications.
        Find prompt injection vulnerabilities before attackers do.
      </p>

      {/* Stats */}
      <div className="flex flex-wrap justify-center gap-8 md:gap-12">
        <div className="text-center">
          <p className="text-2xl font-bold text-foreground">12+</p>
          <p className="text-sm text-muted-foreground">Attack Vectors</p>
        </div>
        <div className="text-center">
          <p className="text-2xl font-bold text-foreground">4</p>
          <p className="text-sm text-muted-foreground">Categories</p>
        </div>
        <div className="text-center">
          <p className="text-2xl font-bold text-foreground">&lt;30s</p>
          <p className="text-sm text-muted-foreground">Full Scan</p>
        </div>
      </div>
    </div>
  )
}
