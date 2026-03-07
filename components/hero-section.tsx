'use client'

export function HeroSection() {
  return (
    <div className="text-center mb-16">
      {/* Badge */}
      <div className="inline-flex items-center gap-2 px-3 py-1.5 mb-8 text-xs font-medium rounded-full bg-secondary border border-border text-muted-foreground">
        <span className="w-1.5 h-1.5 rounded-full bg-success animate-pulse" />
        AI 安全红队演练平台
      </div>

      {/* Main Headline */}
      <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold text-foreground mb-6 leading-tight tracking-tight text-balance">
        你的 AI 应用
        <br />
        <span className="text-accent">够安全吗？</span>
      </h1>

      {/* Subtitle */}
      <p className="text-lg text-muted-foreground max-w-xl mx-auto mb-4 leading-relaxed text-pretty">
        AntiClaude 是面向开发者的 LLM 自动化渗透测试平台。
        在攻击者发现漏洞之前，先一步发现并修复它们。
      </p>
      
      <p className="text-sm text-muted-foreground/80 max-w-lg mx-auto mb-10">
        输入您的 AI API 端点，我们会自动发起模拟攻击，检测提示词泄漏、越狱等常见漏洞。
      </p>

      {/* Stats */}
      <div className="flex flex-wrap justify-center gap-8 md:gap-12 pt-8 border-t border-border">
        <div className="text-center">
          <p className="text-2xl font-bold text-foreground">12+</p>
          <p className="text-sm text-muted-foreground">攻击向量</p>
        </div>
        <div className="text-center">
          <p className="text-2xl font-bold text-foreground">4 类</p>
          <p className="text-sm text-muted-foreground">漏洞类型</p>
        </div>
        <div className="text-center">
          <p className="text-2xl font-bold text-foreground">&lt;30s</p>
          <p className="text-sm text-muted-foreground">完成扫描</p>
        </div>
        <div className="text-center">
          <p className="text-2xl font-bold text-foreground">免费</p>
          <p className="text-sm text-muted-foreground">MVP 版本</p>
        </div>
      </div>
    </div>
  )
}
