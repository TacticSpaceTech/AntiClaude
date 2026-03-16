import type { Metadata } from 'next'
import Link from 'next/link'
import { SubPageHeader } from '@/components/sub-page-header'
import { notFound } from 'next/navigation'
import { posts } from '@/content/blog/posts'

interface Props {
  params: Promise<{ slug: string }>
}

export async function generateStaticParams() {
  return posts.map((post) => ({ slug: post.slug }))
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { slug } = await params
  const post = posts.find((p) => p.slug === slug)
  if (!post) return { title: 'Post Not Found - AntiClaude' }
  return {
    title: `${post.title} - AntiClaude Blog`,
    description: post.description,
  }
}

export default async function BlogPostPage({ params }: Props) {
  const { slug } = await params
  const post = posts.find((p) => p.slug === slug)

  if (!post) {
    notFound()
  }

  const jsonLd = {
    '@context': 'https://schema.org',
    '@type': 'Article',
    headline: post.title,
    datePublished: post.date,
    author: { '@type': 'Organization', name: 'TacticSpaceTech' },
    publisher: { '@type': 'Organization', name: 'AntiClaude' },
    description: post.description,
  }

  return (
    <div className="min-h-screen bg-background">
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
      <SubPageHeader active="/blog" />

      <main className="max-w-3xl mx-auto px-6 py-12 pb-24">
        <article>
          <div className="mb-10">
            <div className="flex items-center gap-3 text-xs font-mono text-muted-foreground mb-4">
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
            <h1 className="text-3xl md:text-4xl font-mono font-bold text-foreground leading-tight">
              {post.title}
            </h1>
          </div>

          <div className="border-t border-border pt-8">
            {post.content}
          </div>
        </article>

        <div className="mt-16 pt-8 border-t border-border">
          <Link
            href="/blog"
            className="text-sm font-mono text-primary/70 hover:text-primary transition-colors"
          >
            &larr; Back to all posts
          </Link>
        </div>
      </main>
    </div>
  )
}
