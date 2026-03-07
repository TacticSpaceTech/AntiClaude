'use client'

import { useI18n } from '@/lib/i18n'

export function AboutSection() {
  const { t } = useI18n()
  
  return (
    <section className="py-24 border-t border-primary/10 relative">
      {/* Background effect */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_bottom_left,_rgba(0,255,65,0.03)_0%,_transparent_50%)]" />
      
      <div className="max-w-5xl mx-auto px-6 relative">
        <div className="grid lg:grid-cols-2 gap-16 items-center">
          {/* Left: Vision */}
          <div>
            <p className="text-sm font-mono text-primary/60 mb-3 tracking-wider">
              {'// '}{t('about.label')}
            </p>
            <h2 className="text-3xl md:text-4xl font-bold text-foreground mb-6 text-balance">
              {t('about.title')}
            </h2>
            <div className="space-y-4 text-muted-foreground leading-relaxed">
              <p>{t('about.p1')}</p>
              <p>{t('about.p2')}</p>
              <p>{t('about.p3')}</p>
            </div>
          </div>
          
          {/* Right: Stats & Mission */}
          <div className="space-y-6">
            {/* Mission Card */}
            <div className="p-6 rounded-lg bg-black/40 backdrop-blur-sm border border-primary/20">
              <div className="flex items-center gap-2 mb-3">
                <span className="w-2 h-2 rounded-full bg-primary animate-pulse" />
                <h3 className="text-lg font-semibold text-foreground font-mono">
                  {t('about.missionTitle')}
                </h3>
              </div>
              <p className="text-muted-foreground text-sm leading-relaxed">
                {t('about.missionText')}
              </p>
            </div>
            
            {/* Stats Grid */}
            <div className="grid grid-cols-2 gap-4">
              {[
                { value: '87%', label: t('about.stat1') },
                { value: '12+', label: t('about.stat2') },
                { value: '30s', label: t('about.stat3') },
                { value: '100%', label: t('about.stat4') },
              ].map((stat, index) => (
                <div 
                  key={index}
                  className="p-5 rounded-lg bg-black/40 backdrop-blur-sm border border-primary/20 text-center group hover:border-primary/40 transition-all"
                >
                  <p className="text-3xl font-bold text-primary font-mono mb-1 drop-shadow-[0_0_10px_rgba(0,255,65,0.3)] group-hover:drop-shadow-[0_0_15px_rgba(0,255,65,0.5)] transition-all">
                    {stat.value}
                  </p>
                  <p className="text-xs text-muted-foreground">{stat.label}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}
