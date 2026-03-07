'use client'

import { useEffect, useState, useRef } from 'react'
import { cn } from '@/lib/utils'
import { useI18n } from '@/lib/i18n'

interface CategoryScore {
  category: string
  score: number
  maxScore: number
  vulnerabilities: number
}

interface SecurityRadarChartProps {
  data: CategoryScore[]
  overallScore: number
  isAnimating?: boolean
  className?: string
}

// Category translations
const categoryNames: Record<string, Record<string, string>> = {
  'system_prompt': { zh: '提示词泄露', en: 'Prompt Leak' },
  'jailbreak': { zh: '越狱攻击', en: 'Jailbreak' },
  'format_injection': { zh: '格式注入', en: 'Format Injection' },
  'translation_bypass': { zh: '翻译绕过', en: 'Translation Bypass' },
  'context_manipulation': { zh: '上下文操纵', en: 'Context Hijack' },
  'encoding_bypass': { zh: '编码绕过', en: 'Encoding Bypass' },
}

export function SecurityRadarChart({ 
  data, 
  overallScore,
  isAnimating = false,
  className 
}: SecurityRadarChartProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const { locale } = useI18n()
  const [animationProgress, setAnimationProgress] = useState(0)

  useEffect(() => {
    if (isAnimating) {
      setAnimationProgress(0)
      const duration = 1500
      const startTime = Date.now()
      
      const animate = () => {
        const elapsed = Date.now() - startTime
        const progress = Math.min(elapsed / duration, 1)
        // Easing function for smooth animation
        const eased = 1 - Math.pow(1 - progress, 3)
        setAnimationProgress(eased)
        
        if (progress < 1) {
          requestAnimationFrame(animate)
        }
      }
      requestAnimationFrame(animate)
    } else {
      setAnimationProgress(1)
    }
  }, [isAnimating, data])

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const dpr = window.devicePixelRatio || 1
    const size = 280
    canvas.width = size * dpr
    canvas.height = size * dpr
    canvas.style.width = `${size}px`
    canvas.style.height = `${size}px`
    ctx.scale(dpr, dpr)

    const centerX = size / 2
    const centerY = size / 2
    const maxRadius = size * 0.4
    const numPoints = data.length || 6
    const angleStep = (Math.PI * 2) / numPoints

    // Clear
    ctx.clearRect(0, 0, size, size)

    // Draw grid circles
    const gridLevels = 4
    for (let i = 1; i <= gridLevels; i++) {
      const radius = (maxRadius / gridLevels) * i
      ctx.beginPath()
      ctx.arc(centerX, centerY, radius, 0, Math.PI * 2)
      ctx.strokeStyle = `rgba(0, 255, 65, ${0.1 + i * 0.05})`
      ctx.lineWidth = 1
      ctx.stroke()
    }

    // Draw axis lines
    for (let i = 0; i < numPoints; i++) {
      const angle = i * angleStep - Math.PI / 2
      const x = centerX + Math.cos(angle) * maxRadius
      const y = centerY + Math.sin(angle) * maxRadius
      
      ctx.beginPath()
      ctx.moveTo(centerX, centerY)
      ctx.lineTo(x, y)
      ctx.strokeStyle = 'rgba(0, 255, 65, 0.2)'
      ctx.lineWidth = 1
      ctx.stroke()
    }

    // Draw data polygon
    if (data.length > 0) {
      // Calculate points
      const points: { x: number; y: number; score: number }[] = []
      
      for (let i = 0; i < data.length; i++) {
        const angle = i * angleStep - Math.PI / 2
        const score = (data[i].score / 100) * animationProgress
        const radius = score * maxRadius
        points.push({
          x: centerX + Math.cos(angle) * radius,
          y: centerY + Math.sin(angle) * radius,
          score: data[i].score
        })
      }

      // Draw filled area
      ctx.beginPath()
      points.forEach((point, i) => {
        if (i === 0) {
          ctx.moveTo(point.x, point.y)
        } else {
          ctx.lineTo(point.x, point.y)
        }
      })
      ctx.closePath()
      
      // Gradient fill
      const gradient = ctx.createRadialGradient(centerX, centerY, 0, centerX, centerY, maxRadius)
      gradient.addColorStop(0, 'rgba(0, 255, 65, 0.3)')
      gradient.addColorStop(1, 'rgba(0, 255, 65, 0.05)')
      ctx.fillStyle = gradient
      ctx.fill()

      // Draw outline
      ctx.beginPath()
      points.forEach((point, i) => {
        if (i === 0) {
          ctx.moveTo(point.x, point.y)
        } else {
          ctx.lineTo(point.x, point.y)
        }
      })
      ctx.closePath()
      ctx.strokeStyle = 'rgba(0, 255, 65, 0.8)'
      ctx.lineWidth = 2
      ctx.stroke()

      // Draw vulnerable areas (red overlay)
      const vulnPoints: { x: number; y: number }[] = []
      for (let i = 0; i < data.length; i++) {
        const angle = i * angleStep - Math.PI / 2
        // Low score = more vulnerable
        const vulnScore = ((100 - data[i].score) / 100) * animationProgress
        const radius = vulnScore * maxRadius * 0.5
        vulnPoints.push({
          x: centerX + Math.cos(angle) * radius,
          y: centerY + Math.sin(angle) * radius
        })
      }

      // Draw data points
      points.forEach((point, i) => {
        ctx.beginPath()
        ctx.arc(point.x, point.y, 4, 0, Math.PI * 2)
        
        // Color based on score
        const score = data[i].score
        if (score >= 80) {
          ctx.fillStyle = '#00ff41' // Green - good
        } else if (score >= 50) {
          ctx.fillStyle = '#ffc107' // Yellow - warning
        } else {
          ctx.fillStyle = '#ff5050' // Red - danger
        }
        ctx.fill()
        
        // Glow effect
        ctx.beginPath()
        ctx.arc(point.x, point.y, 6, 0, Math.PI * 2)
        ctx.strokeStyle = score >= 50 ? 'rgba(0, 255, 65, 0.5)' : 'rgba(255, 80, 80, 0.5)'
        ctx.lineWidth = 2
        ctx.stroke()
      })
    }

    // Draw center score
    ctx.font = 'bold 32px Geist Mono, monospace'
    ctx.textAlign = 'center'
    ctx.textBaseline = 'middle'
    const displayScore = Math.round(overallScore * animationProgress)
    
    // Score color
    let scoreColor = '#00ff41'
    if (overallScore < 50) scoreColor = '#ff5050'
    else if (overallScore < 80) scoreColor = '#ffc107'
    
    ctx.fillStyle = scoreColor
    ctx.fillText(`${displayScore}`, centerX, centerY - 8)
    
    ctx.font = '10px Geist Mono, monospace'
    ctx.fillStyle = 'rgba(255, 255, 255, 0.5)'
    ctx.fillText(locale === 'zh' ? '安全评分' : 'SECURITY', centerX, centerY + 16)

  }, [data, animationProgress, locale, overallScore])

  const getLang = () => locale === 'en' ? 'en' : 'zh'

  return (
    <div className={cn('relative', className)}>
      {/* Radar Chart */}
      <div className="flex justify-center">
        <div className="relative">
          <canvas 
            ref={canvasRef}
            className="drop-shadow-[0_0_20px_rgba(0,255,65,0.2)]"
          />
          
          {/* Category labels around the chart */}
          {data.map((item, i) => {
            const angle = (i * (Math.PI * 2) / data.length) - Math.PI / 2
            const labelRadius = 160
            const x = Math.cos(angle) * labelRadius
            const y = Math.sin(angle) * labelRadius
            
            return (
              <div
                key={item.category}
                className="absolute text-[10px] font-mono whitespace-nowrap transform -translate-x-1/2 -translate-y-1/2"
                style={{
                  left: `calc(50% + ${x}px)`,
                  top: `calc(50% + ${y}px)`,
                }}
              >
                <div className={cn(
                  'px-2 py-0.5 rounded',
                  item.score >= 80 ? 'text-primary/80' : 
                  item.score >= 50 ? 'text-warning' : 'text-danger'
                )}>
                  {categoryNames[item.category]?.[getLang()] || item.category}
                </div>
                <div className="text-center text-foreground/40">
                  {Math.round(item.score * animationProgress)}%
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Legend */}
      <div className="mt-6 flex justify-center gap-6 text-xs font-mono">
        <div className="flex items-center gap-1.5">
          <div className="w-2 h-2 rounded-full bg-primary" />
          <span className="text-foreground/50">{locale === 'zh' ? '安全' : 'Safe'} (80+)</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-2 h-2 rounded-full bg-warning" />
          <span className="text-foreground/50">{locale === 'zh' ? '警告' : 'Warning'} (50-79)</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-2 h-2 rounded-full bg-danger" />
          <span className="text-foreground/50">{locale === 'zh' ? '危险' : 'Critical'} (&lt;50)</span>
        </div>
      </div>
    </div>
  )
}
