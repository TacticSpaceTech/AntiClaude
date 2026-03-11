'use client'

import { useState } from 'react'
import { cn } from '@/lib/utils'
import { useI18n } from '@/lib/i18n'

// OWASP LLM Top 10 2025 Categories
interface OWASPCategory {
  id: string
  code: string
  name: { zh: string; en: string }
  description: { zh: string; en: string }
  status: 'passed' | 'failed' | 'warning' | 'not_tested'
  findings: number
  severity: 'critical' | 'high' | 'medium' | 'low'
}

interface OWASPComplianceReportProps {
  categories: OWASPCategory[]
  className?: string
}

// OWASP Agentic Security Initiative Categories
const owaspAgenticTop5: Omit<OWASPCategory, 'status' | 'findings'>[] = [
  {
    id: 'asi01',
    code: 'ASI01',
    name: { zh: 'Agent 目标劫持', en: 'Agent Goal Hijacking' },
    description: {
      zh: '通过提示注入、角色扮演、间接注入等方式劫持 Agent 的原始目标',
      en: 'Hijacking agent goals via prompt injection, roleplay, indirect injection, or persona splitting'
    },
    severity: 'critical'
  },
  {
    id: 'asi02',
    code: 'ASI02',
    name: { zh: '工具滥用与注入', en: 'Tool Misuse & Injection' },
    description: {
      zh: '利用格式注入、参数污染、工具链提权等方式滥用 Agent 工具',
      en: 'Exploiting format injection, parameter pollution, tool chaining, and schema injection to abuse agent tools'
    },
    severity: 'high'
  },
  {
    id: 'asi04',
    code: 'ASI04',
    name: { zh: '供应链漏洞', en: 'Supply Chain Vulnerabilities' },
    description: {
      zh: '依赖混淆、恶意插件、篡改配置、RAG 投毒等供应链攻击',
      en: 'Dependency confusion, malicious plugins, config override, RAG poisoning, and build script injection'
    },
    severity: 'high'
  },
  {
    id: 'asi07',
    code: 'ASI07',
    name: { zh: '系统提示词泄露', en: 'System Prompt Leakage' },
    description: {
      zh: '通过直接提取、格式化诱导、翻译请求等方式泄露系统提示词',
      en: 'Extracting system prompts via direct requests, formatting tricks, translation, completion, and few-shot attacks'
    },
    severity: 'critical'
  },
  {
    id: 'asi08',
    code: 'ASI08',
    name: { zh: '人-Agent 信任操纵', en: 'Human-Agent Trust Manipulation' },
    description: {
      zh: '利用权威冒充、紧急感操纵、情感操控、合规伪装等社会工程手段',
      en: 'Social engineering via authority impersonation, urgency, emotional manipulation, gaslighting, and compliance framing'
    },
    severity: 'high'
  },
]

// Map our attack categories to OWASP Agentic categories
export function mapToOWASP(attackResults: { category: string; leaked: boolean; confidence: number }[]): OWASPCategory[] {
  const categoryMapping: Record<string, string[]> = {
    'jailbreak': ['asi01'],
    'format_injection': ['asi02'],
    'supply_chain': ['asi04'],
    'system_prompt_leak': ['asi07'],
    'trust_manipulation': ['asi08'],
  }

  const owaspResults: Record<string, { findings: number; maxConfidence: number; tested: boolean }> = {}

  for (const category of owaspAgenticTop5) {
    owaspResults[category.id] = { findings: 0, maxConfidence: 0, tested: false }
  }

  for (const result of attackResults) {
    const owaspIds = categoryMapping[result.category] || []
    for (const owaspId of owaspIds) {
      if (owaspResults[owaspId]) {
        owaspResults[owaspId].tested = true
        if (result.leaked) {
          owaspResults[owaspId].findings++
          owaspResults[owaspId].maxConfidence = Math.max(
            owaspResults[owaspId].maxConfidence,
            result.confidence
          )
        }
      }
    }
  }

  return owaspAgenticTop5.map(category => {
    const result = owaspResults[category.id]
    let status: OWASPCategory['status'] = 'not_tested'

    if (result.tested) {
      if (result.findings > 0) {
        status = result.maxConfidence >= 70 ? 'failed' : 'warning'
      } else {
        status = 'passed'
      }
    }

    return {
      ...category,
      status,
      findings: result.findings
    }
  })
}

export function OWASPComplianceReport({ categories, className }: OWASPComplianceReportProps) {
  const { locale } = useI18n()
  const [expandedId, setExpandedId] = useState<string | null>(null)
  
  const getLang = () => locale === 'en' ? 'en' : 'zh'
  
  const getStatusStyle = (status: OWASPCategory['status']) => {
    switch (status) {
      case 'passed':
        return {
          bg: 'bg-primary/10',
          border: 'border-primary/30',
          text: 'text-primary',
          label: getLang() === 'zh' ? '通过' : 'PASS',
          icon: (
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
            </svg>
          )
        }
      case 'failed':
        return {
          bg: 'bg-danger/10',
          border: 'border-danger/30',
          text: 'text-danger',
          label: getLang() === 'zh' ? '不通过' : 'FAIL',
          icon: (
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          )
        }
      case 'warning':
        return {
          bg: 'bg-warning/10',
          border: 'border-warning/30',
          text: 'text-warning',
          label: getLang() === 'zh' ? '警告' : 'WARN',
          icon: (
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          )
        }
      default:
        return {
          bg: 'bg-foreground/5',
          border: 'border-foreground/10',
          text: 'text-foreground/40',
          label: getLang() === 'zh' ? '未测试' : 'N/A',
          icon: (
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          )
        }
    }
  }

  const getSeverityColor = (severity: OWASPCategory['severity']) => {
    switch (severity) {
      case 'critical': return 'text-danger'
      case 'high': return 'text-warning'
      case 'medium': return 'text-primary/70'
      case 'low': return 'text-foreground/50'
    }
  }

  const passedCount = categories.filter(c => c.status === 'passed').length
  const failedCount = categories.filter(c => c.status === 'failed').length
  const warningCount = categories.filter(c => c.status === 'warning').length
  const testedCount = categories.filter(c => c.status !== 'not_tested').length

  return (
    <div className={cn('space-y-4', className)}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-primary/10 border border-primary/30 flex items-center justify-center">
            <svg className="w-5 h-5 text-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <div>
            <h3 className="font-mono font-bold text-foreground">
              OWASP Agentic Security {getLang() === 'zh' ? '合规报告' : 'Compliance'}
            </h3>
            <p className="text-xs text-foreground/50 font-mono">
              {getLang() === 'zh' ? '基于 OWASP Agentic Security Initiative 标准' : 'Based on OWASP Agentic Security Initiative'}
            </p>
          </div>
        </div>

        {/* Summary Stats */}
        <div className="flex items-center gap-4 text-xs font-mono">
          <div className="text-primary">
            <span className="font-bold">{passedCount}</span> {getLang() === 'zh' ? '通过' : 'Pass'}
          </div>
          <div className="text-danger">
            <span className="font-bold">{failedCount}</span> {getLang() === 'zh' ? '失败' : 'Fail'}
          </div>
          <div className="text-warning">
            <span className="font-bold">{warningCount}</span> {getLang() === 'zh' ? '警告' : 'Warn'}
          </div>
          <div className="text-foreground/40">
            {testedCount}/5 {getLang() === 'zh' ? '已测试' : 'Tested'}
          </div>
        </div>
      </div>

      {/* Categories Grid */}
      <div className="space-y-2">
        {categories.map((category) => {
          const style = getStatusStyle(category.status)
          const isExpanded = expandedId === category.id
          
          return (
            <div
              key={category.id}
              className={cn(
                'rounded-lg border transition-all cursor-pointer',
                style.bg,
                style.border,
                isExpanded && 'ring-1 ring-primary/30'
              )}
              onClick={() => setExpandedId(isExpanded ? null : category.id)}
            >
              <div className="flex items-center gap-4 p-3">
                {/* Status Icon */}
                <div className={cn('shrink-0', style.text)}>
                  {style.icon}
                </div>

                {/* Code & Name */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-xs text-foreground/70">
                      {category.code}
                    </span>
                    <span className="font-mono text-sm text-foreground">
                      {category.name[getLang()]}
                    </span>
                  </div>
                  {!isExpanded && (
                    <p className="text-xs text-foreground/40 truncate font-mono">
                      {category.description[getLang()]}
                    </p>
                  )}
                </div>

                {/* Severity & Findings */}
                <div className="flex items-center gap-3 shrink-0">
                  <span className={cn('text-[10px] font-mono uppercase', getSeverityColor(category.severity))}>
                    {category.severity}
                  </span>
                  {category.findings > 0 && (
                    <span className="text-xs font-mono text-danger">
                      {category.findings} {getLang() === 'zh' ? '发现' : 'findings'}
                    </span>
                  )}
                  <span className={cn('text-xs font-mono font-bold', style.text)}>
                    {style.label}
                  </span>
                  <svg 
                    className={cn(
                      'w-4 h-4 text-foreground/30 transition-transform',
                      isExpanded && 'rotate-180'
                    )} 
                    fill="none" 
                    viewBox="0 0 24 24" 
                    stroke="currentColor"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </div>
              </div>

              {/* Expanded Content */}
              {isExpanded && (
                <div className="px-4 pb-4 pt-2 border-t border-foreground/5">
                  <p className="text-sm text-foreground/60 mb-3">
                    {category.description[getLang()]}
                  </p>
                  
                  {category.status === 'failed' && (
                    <div className="bg-danger/5 border border-danger/20 rounded p-3">
                      <div className="flex items-center gap-2 mb-2">
                        <svg className="w-4 h-4 text-danger" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                        </svg>
                        <span className="text-xs font-mono text-danger font-bold">
                          {getLang() === 'zh' ? '安全建议' : 'Recommendation'}
                        </span>
                      </div>
                      <p className="text-xs text-foreground/60 font-mono">
                        {getLang() === 'zh' 
                          ? '建议立即修复此漏洞。参考 OWASP 指南实施相应的防护措施。'
                          : 'Immediate remediation recommended. Implement countermeasures per OWASP guidelines.'
                        }
                      </p>
                    </div>
                  )}
                  
                  {category.status === 'not_tested' && (
                    <div className="text-xs text-foreground/40 font-mono italic">
                      {getLang() === 'zh' 
                        ? '此类别需要更深入的测试。建议使用完整版 AntiClaude 进行全面评估。'
                        : 'This category requires deeper testing. Consider full AntiClaude assessment.'
                      }
                    </div>
                  )}
                </div>
              )}
            </div>
          )
        })}
      </div>

      {/* OWASP Badge */}
      <div className="flex items-center justify-center pt-4">
        <div className="flex items-center gap-2 px-4 py-2 rounded-lg bg-foreground/5 border border-foreground/10">
          <span className="text-[10px] font-mono text-foreground/40">
            {getLang() === 'zh' ? '合规标准' : 'Compliance Standard'}:
          </span>
          <span className="text-xs font-mono text-primary font-bold">
            OWASP LLM Top 10 v2025
          </span>
        </div>
      </div>
    </div>
  )
}
