'use client'

import { useState } from 'react'
import { ChevronDown } from 'lucide-react'
import { cn } from '@/lib/utils'

const faqs = [
  {
    question: 'AntiClaude 支持哪些 AI 模型和平台？',
    answer: '我们支持任何通过 HTTP API 暴露的 AI 应用，包括但不限于 OpenAI、Anthropic Claude、Google Gemini、以及自建的开源模型。只要您的应用能接收文本输入并返回响应，AntiClaude 就能测试它。'
  },
  {
    question: '测试过程中我的数据安全吗？',
    answer: '绝对安全。所有测试数据在传输过程中使用 TLS 加密，测试完成后立即从我们的服务器删除。我们不会存储您的 API 密钥、系统提示词或任何敏感信息。我们的基础设施符合 SOC 2 Type II 和 GDPR 合规要求。'
  },
  {
    question: '发现漏洞后如何修复？',
    answer: '每份安全报告都包含针对性的修复建议。对于提示词泄漏，我们会提供防御性指令模板；对于越狱攻击，我们会建议系统级的安全策略。您可以直接复制这些补丁到您的应用中。'
  },
  {
    question: 'MVP 版本是免费的吗？',
    answer: '是的，当前 MVP 版本完全免费使用。每次扫描包含 5 个高风险攻击向量的测试。我们计划在未来推出付费版本，提供更全面的扫描、CI/CD 集成和企业级支持。'
  },
  {
    question: '如何将 AntiClaude 集成到 CI/CD 流程？',
    answer: '这项功能正在开发中。我们即将推出 GitHub Actions 和 GitLab CI 的官方集成，让您可以在每次代码提交时自动运行安全扫描。提前留下邮箱，我们会在功能上线后第一时间通知您。'
  },
  {
    question: '测试会影响我的生产环境吗？',
    answer: '我们建议您使用测试环境或沙箱环境进行扫描。AntiClaude 发送的是标准的文本请求，不会执行任何破坏性操作，但为了安全起见，请确保测试端点有适当的速率限制。'
  }
]

export function FAQSection() {
  const [openIndex, setOpenIndex] = useState<number | null>(0)
  
  return (
    <section className="py-24 border-t border-border">
      <div className="max-w-3xl mx-auto px-6">
        <div className="text-center mb-16">
          <p className="text-sm font-medium text-muted-foreground mb-3 tracking-wide uppercase">
            常见问题
          </p>
          <h2 className="text-3xl md:text-4xl font-bold text-foreground mb-4 text-balance">
            有疑问？我们来解答
          </h2>
        </div>
        
        <div className="space-y-3">
          {faqs.map((faq, index) => (
            <div 
              key={index}
              className="border border-border rounded-xl overflow-hidden"
            >
              <button
                onClick={() => setOpenIndex(openIndex === index ? null : index)}
                className="w-full p-5 text-left flex items-center justify-between gap-4 bg-card hover:bg-card/80 transition-colors"
              >
                <span className="font-medium text-foreground">
                  {faq.question}
                </span>
                <ChevronDown 
                  className={cn(
                    "w-5 h-5 text-muted-foreground shrink-0 transition-transform",
                    openIndex === index && "rotate-180"
                  )}
                />
              </button>
              <div 
                className={cn(
                  "grid transition-all duration-200",
                  openIndex === index ? "grid-rows-[1fr]" : "grid-rows-[0fr]"
                )}
              >
                <div className="overflow-hidden">
                  <p className="p-5 pt-0 text-sm text-muted-foreground leading-relaxed">
                    {faq.answer}
                  </p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
