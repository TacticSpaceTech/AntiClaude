'use client'

import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { X, Mail, Shield, CheckCircle2 } from 'lucide-react'
import { cn } from '@/lib/utils'

interface EmailCaptureModalProps {
  isOpen: boolean
  onClose: () => void
  onSubmit: (email: string) => void
  vulnerabilityCount: number
}

export function EmailCaptureModal({ isOpen, onClose, onSubmit, vulnerabilityCount }: EmailCaptureModalProps) {
  const [email, setEmail] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [isSubmitted, setIsSubmitted] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!email.trim()) return

    setIsSubmitting(true)
    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 1000))
    setIsSubmitting(false)
    setIsSubmitted(true)
    
    setTimeout(() => {
      onSubmit(email)
      setIsSubmitted(false)
      setEmail('')
    }, 1500)
  }

  const isValidEmail = (email: string) => {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  }

  if (!isOpen) return null

  return (
    <div 
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-sm animate-in fade-in"
      onClick={onClose}
    >
      <div 
        className="relative w-full max-w-md bg-card border border-border rounded-xl shadow-2xl animate-in zoom-in-95"
        onClick={e => e.stopPropagation()}
      >
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-muted-foreground hover:text-foreground transition-colors"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="p-6">
          {isSubmitted ? (
            <div className="text-center py-8 animate-in fade-in">
              <CheckCircle2 className="w-16 h-16 text-terminal-green mx-auto mb-4" />
              <h3 className="text-xl font-bold text-foreground mb-2">
                Report Unlocked!
              </h3>
              <p className="text-muted-foreground">
                Loading your full security report...
              </p>
            </div>
          ) : (
            <>
              {/* Header */}
              <div className="text-center mb-6">
                <div className="w-16 h-16 bg-cyber-red/10 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Shield className="w-8 h-8 text-cyber-red" />
                </div>
                <h2 className="text-xl font-bold text-foreground mb-2">
                  Your AI Has Vulnerabilities
                </h2>
                <p className="text-muted-foreground">
                  We detected{' '}
                  <span className="text-cyber-red font-semibold">
                    {vulnerabilityCount} potential security issues
                  </span>
                  . Enter your work email to unlock the full report with fix recommendations.
                </p>
              </div>

              {/* Form */}
              <form onSubmit={handleSubmit} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="email" className="text-foreground">
                    Work Email
                  </Label>
                  <div className="relative">
                    <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <Input
                      id="email"
                      type="email"
                      placeholder="you@company.com"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className="pl-10 bg-input border-border text-foreground placeholder:text-muted-foreground"
                      disabled={isSubmitting}
                    />
                  </div>
                </div>

                <Button
                  type="submit"
                  disabled={isSubmitting || !email || !isValidEmail(email)}
                  className={cn(
                    'w-full py-5 font-semibold',
                    'bg-primary hover:bg-primary/90 text-primary-foreground'
                  )}
                >
                  {isSubmitting ? (
                    <span className="animate-pulse">Unlocking...</span>
                  ) : (
                    'Unlock Full Report'
                  )}
                </Button>
              </form>

              {/* Benefits */}
              <div className="mt-6 pt-6 border-t border-border">
                <p className="text-xs text-muted-foreground text-center mb-3">
                  What you&apos;ll get:
                </p>
                <ul className="space-y-2 text-sm text-muted-foreground">
                  <li className="flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-terminal-green shrink-0" />
                    Complete vulnerability analysis
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-terminal-green shrink-0" />
                    Copy-paste security patches
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-terminal-green shrink-0" />
                    Priority security updates
                  </li>
                </ul>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
