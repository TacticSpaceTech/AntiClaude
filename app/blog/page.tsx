import type { Metadata } from 'next'
import Link from 'next/link'
import { posts } from '@/content/blog/posts'

export const metadata: Metadata = {
  title: 'Blog - AntiClaude',
  description: 'Articles about AI agent security, red teaming, OWASP Agentic Top 10, and MCP server hardening.',
}

export default function BlogPage() {
  const sortedPosts = [...posts].sort(
    (a, b) => new Date(b.date).getTime() - new Date(a.date).getTime()
  )

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b border-primary/20 bg-background/90 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-4xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2.5 hover:opacity-80 transition-opacity">
            <img src="/icon-192x192.png" alt="AntiClaude" className="w-8 h-8 rounded" />
            <span className="font-semibold text-primary text-lg font-mono">AntiClaude</span>
          </Link>
          <Link href="/" className="text-sm text-muted-foreground hover:text-foreground transition-colors font-mono">
            &larr; Home
          </Link>
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-6 py-12 pb-24">
        <div className="mb-12">
          <p className="text-sm font-mono text-primary/60 mb-2">// blog</p>
          <h1 className="text-4xl font-mono font-bold text-foreground mb-4">Blog</h1>
          <p className="text-muted-foreground leading-relaxed max-w-2xl">
            Articles about AI agent security, red teaming techniques, and building safer
            AI-powered applications.
          </p>
        </div>

        <div className="space-y-6">
          {sortedPosts.map((post) => (
            <Link
              key={post.slug}
              href={`/blog/${post.slug}`}
              className="group block bg-card/80 border border-border rounded-lg p-6 hover:border-primary/40 transition-colors"
            >
              <div className="flex items-center gap-3 text-xs font-mono text-muted-foreground mb-3">
                <time dateTime={post.date}>
                  {new Date(post.date).toLocaleDateString('en-US', {
                    year: 'numeric',
                    month: 'long',
                    day: 'numeric',
                  })}
                </time>
                <span className="text-primary/30">/</span>
                <span>{post.readingTime}</span>
              </div>
              <h2 className="text-xl font-mono font-semibold text-foreground group-hover:text-primary transition-colors mb-2">
                {post.title}
              </h2>
              <p className="text-sm text-muted-foreground leading-relaxed">
                {post.description}
              </p>
              <span className="inline-block mt-4 text-sm font-mono text-primary/70 group-hover:text-primary transition-colors">
                Read more &rarr;
              </span>
            </Link>
          ))}
        </div>
      </main>
    </div>
  )
}
