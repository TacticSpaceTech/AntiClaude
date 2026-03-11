'use client'

import { useState } from 'react'
import { useI18n } from '@/lib/i18n'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { ChevronDown, ChevronUp, Zap, Key } from 'lucide-react'

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
  const [error, setError] = useState('')

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    
    if (!endpoint.trim()) {
      setError('Target endpoint required')
      return
    }

    try {
      new URL(endpoint)
    } catch {
      setError('Invalid URL format')
      return
    }

    onStartAttack({
      endpoint: endpoint.trim(),
      authHeader: authHeader.trim() || undefined,
      payloadCount: 8
    })
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {/* Main Input - Matrix Style */}
      <div className="relative group">
        {/* Glow effect */}
        <div className="absolute -inset-1 bg-gradient-to-r from-primary/30 via-primary/10 to-primary/30 rounded-lg blur-sm opacity-50 group-hover:opacity-75 transition-opacity" />
        
        <div className="relative bg-black/80 backdrop-blur-sm rounded-lg border border-primary/40 overflow-hidden">
          {/* Terminal header */}
          <div className="flex items-center gap-2 px-4 py-2 border-b border-primary/20 bg-black/40">
            <div className="flex gap-1.5">
              <div className="w-2.5 h-2.5 rounded-full bg-danger" />
              <div className="w-2.5 h-2.5 rounded-full bg-warning" />
              <div className="w-2.5 h-2.5 rounded-full bg-primary shadow-[0_0_6px_rgba(0,255,65,0.6)]" />
            </div>
            <span className="text-xs text-primary/60 font-mono ml-2">{t('form.endpoint')}</span>
          </div>
          
          {/* Input area */}
          <div className="flex items-center">
            <span className="text-primary font-mono pl-4 pr-2 text-sm drop-shadow-[0_0_5px_rgba(0,255,65,0.5)]">{'>'}_</span>
            <Input
              type="url"
              placeholder={t('form.endpointPlaceholder')}
              value={endpoint}
              onChange={(e) => {
                setEndpoint(e.target.value)
                setError('')
              }}
              className="flex-1 bg-transparent border-0 text-primary placeholder:text-primary/30 focus-visible:ring-0 font-mono text-sm h-14"
              disabled={isRunning}
            />
            <Button
              type="submit"
              disabled={isRunning || !endpoint.trim()}
              className="m-2 px-6 h-10 bg-primary text-primary-foreground hover:bg-primary/90 font-mono font-bold shadow-[0_0_25px_rgba(0,255,65,0.4)] hover:shadow-[0_0_35px_rgba(0,255,65,0.6)] transition-all disabled:opacity-40 disabled:shadow-none"
            >
              {isRunning ? (
                <span className="flex items-center gap-2">
                  <span className="w-2 h-2 bg-primary-foreground rounded-full animate-pulse" />
                  {t('form.scanning')}
                </span>
              ) : (
                <span className="flex items-center gap-2">
                  <Zap className="w-4 h-4" />
                  {t('form.startScan')}
                </span>
              )}
            </Button>
          </div>
        </div>
      </div>

      {/* Error */}
      {error && (
        <p className="text-danger text-sm font-mono pl-4 flex items-center gap-2">
          <span>[ERR]</span> {error}
        </p>
      )}

      {/* Advanced Toggle */}
      <button
        type="button"
        onClick={() => setShowAdvanced(!showAdvanced)}
        className="flex items-center gap-2 text-xs text-primary/50 hover:text-primary/80 transition-colors font-mono"
      >
        {showAdvanced ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
        {'// '}{t('form.advanced')}
      </button>

      {/* Advanced Options */}
      {showAdvanced && (
        <div className="bg-black/60 backdrop-blur-sm border border-primary/20 rounded-lg p-4 animate-in fade-in slide-in-from-top-2 duration-200">
          <div className="flex items-center gap-2 mb-3">
            <Key className="w-4 h-4 text-primary/50" />
            <span className="text-xs text-primary/60 font-mono">
              {t('form.authHeader')}
            </span>
          </div>
          <Input
            type="text"
            placeholder={t('form.authHeaderPlaceholder')}
            value={authHeader}
            onChange={(e) => setAuthHeader(e.target.value)}
            className="bg-black/40 border-primary/20 text-primary placeholder:text-primary/30 focus-visible:ring-primary/50 font-mono text-sm"
            disabled={isRunning}
          />
          <p className="text-xs text-primary/40 mt-2 font-mono">
            {'// '}{t('form.authHint')}
          </p>
        </div>
      )}

      {/* Notice */}
      <div className="flex items-start gap-3 p-3 bg-black/40 border border-primary/10 rounded-lg">
        <span className="text-primary/40 font-mono text-xs shrink-0">[INFO]</span>
        <p className="text-xs text-primary/40 leading-relaxed font-mono">
          {t('form.notice')}
        </p>
      </div>
    </form>
  )
}
