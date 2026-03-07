'use client'

import { Shield, Zap, Target, Lock } from 'lucide-react'

export function HeroSection() {
  return (
    <div className="text-center mb-12">
      {/* Logo */}
      <div className="inline-flex items-center justify-center gap-2 mb-6">
        <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center border border-primary/30">
          <Shield className="w-7 h-7 text-primary" />
        </div>
        <span className="text-2xl font-bold text-foreground tracking-tight">
          AntiClaude
        </span>
      </div>

      {/* Tagline */}
      <p className="text-terminal-green text-sm font-mono mb-4 tracking-wider">
        LLM Red Teaming Platform
      </p>

      {/* Main Headline */}
      <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold text-foreground mb-6 leading-tight text-balance">
        Is your AI Agent{' '}
        <span className="text-transparent bg-clip-text bg-gradient-to-r from-primary to-terminal-green">
          bulletproof?
        </span>
      </h1>

      {/* Subtitle */}
      <p className="text-lg text-muted-foreground max-w-2xl mx-auto mb-8 text-pretty">
        Automated penetration testing for LLM applications. 
        Discover prompt injection vulnerabilities before hackers do.
      </p>

      {/* Feature Pills */}
      <div className="flex flex-wrap justify-center gap-3 mb-8">
        <div className="flex items-center gap-2 px-4 py-2 bg-secondary rounded-full border border-border">
          <Zap className="w-4 h-4 text-terminal-amber" />
          <span className="text-sm text-foreground">Prompt Injection</span>
        </div>
        <div className="flex items-center gap-2 px-4 py-2 bg-secondary rounded-full border border-border">
          <Target className="w-4 h-4 text-cyber-red" />
          <span className="text-sm text-foreground">Jailbreak Detection</span>
        </div>
        <div className="flex items-center gap-2 px-4 py-2 bg-secondary rounded-full border border-border">
          <Lock className="w-4 h-4 text-cyber-blue" />
          <span className="text-sm text-foreground">System Prompt Leak</span>
        </div>
      </div>
    </div>
  )
}
