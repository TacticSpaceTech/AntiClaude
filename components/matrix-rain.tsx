'use client'

import { useEffect, useRef } from 'react'

export function MatrixRain() {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const ctx = canvas.getContext('2d')
    if (!ctx) return

    // Set canvas size
    const resizeCanvas = () => {
      canvas.width = window.innerWidth
      canvas.height = window.innerHeight
    }
    resizeCanvas()
    window.addEventListener('resize', resizeCanvas)

    // Matrix characters - mix of katakana, latin, numbers, and symbols
    const chars = 'アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲンABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()_+-=[]{}|;:,./<>?~'
    const charArray = chars.split('')

    const fontSize = 14
    const columns = Math.floor(canvas.width / fontSize)
    
    // Array to track y position of each column
    const drops: number[] = Array(columns).fill(1)
    
    // Random speeds for each column
    const speeds: number[] = Array(columns).fill(0).map(() => Math.random() * 0.5 + 0.5)

    const draw = () => {
      // Semi-transparent black to create fade effect
      ctx.fillStyle = 'rgba(0, 5, 2, 0.05)'
      ctx.fillRect(0, 0, canvas.width, canvas.height)

      for (let i = 0; i < drops.length; i++) {
        // Random character
        const char = charArray[Math.floor(Math.random() * charArray.length)]
        
        // Calculate brightness based on position (newer = brighter)
        const brightness = Math.random()
        
        if (brightness > 0.95) {
          // Bright green for leading characters
          ctx.fillStyle = '#00ff41'
          ctx.shadowColor = '#00ff41'
          ctx.shadowBlur = 10
        } else if (brightness > 0.8) {
          // Medium bright
          ctx.fillStyle = '#00cc33'
          ctx.shadowBlur = 5
        } else {
          // Dimmer green
          ctx.fillStyle = `rgba(0, ${Math.floor(150 + Math.random() * 50)}, ${Math.floor(30 + Math.random() * 30)}, ${0.5 + Math.random() * 0.3})`
          ctx.shadowBlur = 0
        }

        ctx.font = `${fontSize}px "Geist Mono", monospace`
        ctx.fillText(char, i * fontSize, drops[i] * fontSize)
        
        // Reset shadow
        ctx.shadowBlur = 0

        // Reset drop to top with random delay
        if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
          drops[i] = 0
        }

        drops[i] += speeds[i]
      }
    }

    const interval = setInterval(draw, 33) // ~30fps

    return () => {
      clearInterval(interval)
      window.removeEventListener('resize', resizeCanvas)
    }
  }, [])

  return (
    <canvas
      ref={canvasRef}
      className="fixed inset-0 pointer-events-none"
      style={{ zIndex: 0 }}
    />
  )
}
