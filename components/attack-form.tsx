'use client'

import { useState } from 'react'
import { useI18n } from '@/lib/i18n'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { ChevronDown, ChevronUp, Info, Play } from 'lucide-react'

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
  const { t } = useI18n()
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
    <form onSubmit={handleSubmit} className="space-y-5">
      {/* Main Input */}
      <div className="space-y-2">
        <Label htmlFor="endpoint" className="text-sm font-medium text-foreground">
          {t('form.endpoint')}
        </Label>
        <Input
          id="endpoint"
          type="url"
          placeholder={t('form.endpointPlaceholder')}
          value={endpoint}
          onChange={(e) => setEndpoint(e.target.value)}
          className="h-12 bg-input border-border text-foreground placeholder:text-muted-foreground font-mono text-sm"
          disabled={isRunning}
        />
        <p className="text-xs text-muted-foreground">
          {t('form.endpointHint')}
        </p>
      </div>

      {/* Advanced Toggle */}
      <button
        type="button"
        onClick={() => setShowAdvanced(!showAdvanced)}
        className="flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors"
      >
        {showAdvanced ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        {t('form.advanced')}
      </button>

      {showAdvanced && (
        <div className="space-y-2 animate-in fade-in slide-in-from-top-2 duration-200">
          <Label htmlFor="auth" className="text-sm font-medium text-foreground">
            {t('form.authHeader')}
          </Label>
          <Input
            id="auth"
            type="text"
            placeholder={t('form.authHeaderPlaceholder')}
            value={authHeader}
            onChange={(e) => setAuthHeader(e.target.value)}
            className="h-12 bg-input border-border text-foreground placeholder:text-muted-foreground font-mono text-sm"
            disabled={isRunning}
          />
          <p className="text-xs text-muted-foreground">
            {t('form.authHint')}
          </p>
        </div>
      )}

      {/* Notice */}
      <div className="flex items-start gap-3 p-3 bg-secondary/50 border border-border rounded-lg">
        <Info className="w-4 h-4 text-muted-foreground shrink-0 mt-0.5" />
        <p className="text-xs text-muted-foreground leading-relaxed">
          {t('form.notice')}
        </p>
      </div>

      {/* Submit Button */}
      <Button
        type="submit"
        disabled={isRunning || !endpoint || !isValidUrl(endpoint)}
        className="w-full h-12 bg-foreground hover:bg-foreground/90 text-background font-medium text-sm"
      >
        {isRunning ? (
          <span className="flex items-center gap-2">
            <span className="w-4 h-4 border-2 border-background/30 border-t-background rounded-full animate-spin" />
            {t('form.scanning')}
          </span>
        ) : (
          <span className="flex items-center gap-2">
            <Play className="w-4 h-4" />
            {t('form.startScan')}
          </span>
        )}
      </Button>
    </form>
  )
}
