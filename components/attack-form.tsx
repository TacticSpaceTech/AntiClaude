'use client'

import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Shield, Zap, AlertTriangle } from 'lucide-react'

interface AttackFormProps {
  onStartAttack: (config: AttackConfig) => void
  isRunning: boolean
}

export interface AttackConfig {
  endpoint: string
  authHeader?: string
  payloadCount: number
}

export function AttackForm({ onStartAttack, isRunning }: AttackFormProps) {
  const [endpoint, setEndpoint] = useState('')
  const [authHeader, setAuthHeader] = useState('')
  const [showAdvanced, setShowAdvanced] = useState(false)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!endpoint.trim()) return

    onStartAttack({
      endpoint: endpoint.trim(),
      authHeader: authHeader.trim() || undefined,
      payloadCount: 5
    })
  }

  const isValidUrl = (url: string) => {
    try {
      new URL(url)
      return true
    } catch {
      return false
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      <div className="space-y-2">
        <Label htmlFor="endpoint" className="text-foreground flex items-center gap-2">
          <Zap className="w-4 h-4 text-terminal-amber" />
          Target API Endpoint
        </Label>
        <Input
          id="endpoint"
          type="url"
          placeholder="https://api.your-ai-app.com/chat"
          value={endpoint}
          onChange={(e) => setEndpoint(e.target.value)}
          className="bg-input border-border text-foreground placeholder:text-muted-foreground font-mono"
          disabled={isRunning}
        />
        <p className="text-xs text-muted-foreground">
          Enter the API endpoint of your AI application that accepts user messages
        </p>
      </div>

      <button
        type="button"
        onClick={() => setShowAdvanced(!showAdvanced)}
        className="text-sm text-muted-foreground hover:text-foreground transition-colors"
      >
        {showAdvanced ? '- Hide' : '+ Show'} Advanced Options
      </button>

      {showAdvanced && (
        <div className="space-y-2 animate-in fade-in slide-in-from-top-2">
          <Label htmlFor="auth" className="text-foreground flex items-center gap-2">
            <Shield className="w-4 h-4 text-cyber-blue" />
            Authorization Header (Optional)
          </Label>
          <Input
            id="auth"
            type="text"
            placeholder="Bearer sk-xxx..."
            value={authHeader}
            onChange={(e) => setAuthHeader(e.target.value)}
            className="bg-input border-border text-foreground placeholder:text-muted-foreground font-mono"
            disabled={isRunning}
          />
          <p className="text-xs text-muted-foreground">
            If your API requires authentication, provide the header value
          </p>
        </div>
      )}

      <div className="flex items-start gap-2 p-3 bg-secondary/50 border border-border rounded-lg">
        <AlertTriangle className="w-4 h-4 text-terminal-amber shrink-0 mt-0.5" />
        <p className="text-xs text-muted-foreground">
          Only test APIs that you own or have explicit permission to test. 
          AntiClaude sends safe, non-destructive payloads designed to detect prompt vulnerabilities.
        </p>
      </div>

      <Button
        type="submit"
        disabled={isRunning || !endpoint || !isValidUrl(endpoint)}
        className="w-full bg-primary hover:bg-primary/90 text-primary-foreground font-semibold py-6 text-lg"
      >
        {isRunning ? (
          <>
            <span className="animate-pulse">Attacking...</span>
          </>
        ) : (
          <>
            <Zap className="w-5 h-5 mr-2" />
            Start Attack
          </>
        )}
      </Button>
    </form>
  )
}
