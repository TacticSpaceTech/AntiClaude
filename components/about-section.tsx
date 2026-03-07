'use client'

export function AboutSection() {
  return (
    <section className="py-24 border-t border-border">
      <div className="max-w-5xl mx-auto px-6">
        <div className="grid lg:grid-cols-2 gap-16 items-center">
          {/* Left: Vision */}
          <div>
            <p className="text-sm font-medium text-muted-foreground mb-3 tracking-wide uppercase">
              我们的愿景
            </p>
            <h2 className="text-3xl md:text-4xl font-bold text-foreground mb-6 text-balance">
              让每一个 AI 应用<br />都能抵御攻击
            </h2>
            <div className="space-y-4 text-muted-foreground leading-relaxed">
              <p>
                大型语言模型正在重塑软件的形态，但它们的安全性远未跟上发展速度。提示词注入、越狱攻击、数据泄漏 —— 这些威胁每天都在发生，却鲜有有效的防御工具。
              </p>
              <p>
                AntiClaude 诞生于一个简单的信念：<strong className="text-foreground">安全测试不应该是大企业的专利</strong>。我们将专业的红队演练能力封装成开发者友好的工具，让独立开发者和初创团队也能像 Fortune 500 企业一样保护自己的 AI 产品。
              </p>
              <p>
                我们的目标不是取代安全团队，而是成为每个 AI 开发者工具链中不可或缺的一环。
              </p>
            </div>
          </div>
          
          {/* Right: Stats & Mission */}
          <div className="space-y-8">
            {/* Mission Card */}
            <div className="p-6 rounded-xl bg-card border border-border">
              <h3 className="text-lg font-semibold text-foreground mb-3">
                我们的使命
              </h3>
              <p className="text-muted-foreground text-sm leading-relaxed">
                通过自动化的对抗性测试，帮助开发者在黑客之前发现漏洞。我们相信，主动防御是最好的安全策略。
              </p>
            </div>
            
            {/* Stats Grid */}
            <div className="grid grid-cols-2 gap-4">
              <div className="p-6 rounded-xl bg-card border border-border text-center">
                <p className="text-3xl font-bold text-foreground mb-1">87%</p>
                <p className="text-sm text-muted-foreground">AI 应用存在提示词泄漏风险</p>
              </div>
              <div className="p-6 rounded-xl bg-card border border-border text-center">
                <p className="text-3xl font-bold text-foreground mb-1">12+</p>
                <p className="text-sm text-muted-foreground">高风险攻击向量覆盖</p>
              </div>
              <div className="p-6 rounded-xl bg-card border border-border text-center">
                <p className="text-3xl font-bold text-foreground mb-1">30s</p>
                <p className="text-sm text-muted-foreground">完成一次完整扫描</p>
              </div>
              <div className="p-6 rounded-xl bg-card border border-border text-center">
                <p className="text-3xl font-bold text-foreground mb-1">100%</p>
                <p className="text-sm text-muted-foreground">零代码集成</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}
