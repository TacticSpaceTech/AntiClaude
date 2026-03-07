'use client'

const steps = [
  {
    number: '01',
    title: '输入 API 端点',
    description: '提供您 AI 应用的 API 地址和认证信息。支持 REST API、WebSocket 等多种接口类型。'
  },
  {
    number: '02',
    title: '自动化攻击测试',
    description: 'AntiClaude 从弹药库中选取高风险攻击向量，向您的应用发起模拟攻击，实时监测响应。'
  },
  {
    number: '03',
    title: '智能漏洞分析',
    description: '利用专有检测算法分析 AI 响应，识别提示词泄漏、越狱成功等安全事件，计算风险等级。'
  },
  {
    number: '04',
    title: '获取修复方案',
    description: '生成详细报告，提供可直接复制的防御性提示词补丁和最佳实践建议。'
  }
]

export function HowItWorksSection() {
  return (
    <section className="py-24 border-t border-border bg-card/50">
      <div className="max-w-5xl mx-auto px-6">
        <div className="text-center mb-16">
          <p className="text-sm font-medium text-muted-foreground mb-3 tracking-wide uppercase">
            工作原理
          </p>
          <h2 className="text-3xl md:text-4xl font-bold text-foreground mb-4 text-balance">
            四步完成安全体检
          </h2>
          <p className="text-lg text-muted-foreground max-w-2xl mx-auto text-pretty">
            无需专业安全知识，任何开发者都能在几分钟内完成 AI 应用的安全评估
          </p>
        </div>
        
        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-8">
          {steps.map((step, index) => (
            <div key={step.number} className="relative">
              {index < steps.length - 1 && (
                <div className="hidden lg:block absolute top-6 left-full w-full h-px bg-border -translate-x-4" />
              )}
              <div className="text-4xl font-bold text-border mb-4">
                {step.number}
              </div>
              <h3 className="text-lg font-semibold text-foreground mb-2">
                {step.title}
              </h3>
              <p className="text-sm text-muted-foreground leading-relaxed">
                {step.description}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
