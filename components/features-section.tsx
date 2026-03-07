'use client'

import { Shield, Zap, FileText, Code2, Lock, RefreshCw } from 'lucide-react'

const features = [
  {
    icon: Shield,
    title: '全面漏洞扫描',
    description: '覆盖系统提示词泄漏、越狱攻击、格式注入等 12+ 种攻击向量，无死角检测您的 AI 应用安全性。'
  },
  {
    icon: Zap,
    title: '实时攻击反馈',
    description: '可视化攻击终端实时展示测试进度，30秒内完成完整扫描，快速定位安全隐患。'
  },
  {
    icon: FileText,
    title: '专业安全报告',
    description: '生成详细的安全体检报告，包含安全评分、漏洞详情和可直接应用的修复建议。'
  },
  {
    icon: Code2,
    title: '零代码集成',
    description: '无需修改现有代码，只需提供 API 端点即可开始测试。支持各类认证方式。'
  },
  {
    icon: Lock,
    title: '企业级安全',
    description: '所有测试数据端到端加密，测试完成后自动清除。符合 SOC 2 和 GDPR 合规要求。'
  },
  {
    icon: RefreshCw,
    title: 'CI/CD 集成',
    description: '即将推出：与 GitHub Actions 深度集成，每次代码提交自动执行安全扫描。'
  }
]

export function FeaturesSection() {
  return (
    <section className="py-24 border-t border-border">
      <div className="max-w-5xl mx-auto px-6">
        <div className="text-center mb-16">
          <p className="text-sm font-medium text-muted-foreground mb-3 tracking-wide uppercase">
            核心能力
          </p>
          <h2 className="text-3xl md:text-4xl font-bold text-foreground mb-4 text-balance">
            为 AI 应用安全而生
          </h2>
          <p className="text-lg text-muted-foreground max-w-2xl mx-auto text-pretty">
            从漏洞发现到修复建议，AntiClaude 提供端到端的 LLM 安全解决方案
          </p>
        </div>
        
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          {features.map((feature) => (
            <div 
              key={feature.title}
              className="group p-6 rounded-xl bg-card border border-border hover:border-foreground/20 transition-colors"
            >
              <div className="w-10 h-10 rounded-lg bg-secondary flex items-center justify-center mb-4 group-hover:bg-foreground/10 transition-colors">
                <feature.icon className="w-5 h-5 text-foreground" />
              </div>
              <h3 className="text-lg font-semibold text-foreground mb-2">
                {feature.title}
              </h3>
              <p className="text-sm text-muted-foreground leading-relaxed">
                {feature.description}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
