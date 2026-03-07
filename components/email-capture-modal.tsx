'use client'

import { useState } from 'react'
import { useI18n } from '@/lib/i18n'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { X, Mail, CheckCircle2 } from 'lucide-react'

interface EmailCaptureModalProps {
  isOpen: boolean
  onClose: () => void
  onSubmit: (email: string) => void
  vulnerabilityCount: number
}

export function EmailCaptureModal({ isOpen, onClose, onSubmit, vulnerabilityCount }: EmailCaptureModalProps) {
  const { t } = useI18n()
  const [email, setEmail] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [isSubmitted, setIsSubmitted] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!email.trim()) return

    setIsSubmitting(true)
    await new Promise(resolve => setTimeout(resolve, 800))
    setIsSubmitting(false)
    setIsSubmitted(true)
    
    setTimeout(() => {
      onSubmit(email)
      setIsSubmitted(false)
      setEmail('')
    }, 1200)
  }

  const isValidEmail = (email: string) => {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  }

  if (!isOpen) return null

  return (
    <div 
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/90 backdrop-blur-sm animate-in fade-in"
      onClick={onClose}
    >
      <div 
        className="relative w-full max-w-sm bg-card border border-border rounded-2xl shadow-2xl animate-in zoom-in-95"
        onClick={e => e.stopPropagation()}
      >
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 p-1 text-muted-foreground hover:text-foreground transition-colors rounded-md hover:bg-secondary"
        >
          <X className="w-4 h-4" />
        </button>

        <div className="p-6">
          {isSubmitted ? (
            <div className="text-center py-8 animate-in fade-in">
              <div className="w-14 h-14 bg-success/10 rounded-full flex items-center justify-center mx-auto mb-4">
                <CheckCircle2 className="w-7 h-7 text-success" />
              </div>
              <h3 className="text-lg font-semibold text-foreground mb-1">
                {t('email.unlocked')}
              </h3>
              <p className="text-sm text-muted-foreground">
                {t('email.loading')}
              </p>
            </div>
          ) : (
            <>
              {/* Header */}
              <div className="text-center mb-6">
                <div className="w-14 h-14 bg-danger/10 rounded-full flex items-center justify-center mx-auto mb-4">
                  <span className="text-2xl font-bold text-danger">{vulnerabilityCount}</span>
                </div>
                <h2 className="text-lg font-semibold text-foreground mb-2">
                  {t('email.detected')}
                </h2>
                <p className="text-sm text-muted-foreground">
                  {t('email.subtitle')}
                </p>
              </div>

              {/* Form */}
              <form onSubmit={handleSubmit} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="email" className="text-sm font-medium text-foreground">
                    {t('email.label')}
                  </Label>
                  <div className="relative">
                    <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <Input
                      id="email"
                      type="email"
                      placeholder={t('email.placeholder')}
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className="pl-10 h-11 bg-input border-border text-foreground placeholder:text-muted-foreground"
                      disabled={isSubmitting}
                    />
                  </div>
                </div>

                <Button
                  type="submit"
                  disabled={isSubmitting || !email || !isValidEmail(email)}
                  className="w-full h-11 bg-foreground hover:bg-foreground/90 text-background font-medium"
                >
                  {isSubmitting ? (
                    <span className="flex items-center gap-2">
                      <span className="w-4 h-4 border-2 border-background/30 border-t-background rounded-full animate-spin" />
                      {t('email.unlocking')}
                    </span>
                  ) : (
                    t('email.submit')
                  )}
                </Button>
              </form>

              {/* Footer */}
              <p className="text-xs text-muted-foreground text-center mt-4">
                {t('email.privacy')}
              </p>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
