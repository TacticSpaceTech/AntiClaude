import type { MetadataRoute } from 'next'
import { posts } from '@/content/blog/posts'

export default function sitemap(): MetadataRoute.Sitemap {
  const baseUrl = 'https://anticlaude.dev'

  const staticPages = [
    '', '/features', '/docs', '/about', '/enterprise',
    '/cicd', '/blog', '/contact', '/privacy', '/terms',
  ]

  const blogPages = posts.map(post => ({
    url: `${baseUrl}/blog/${post.slug}`,
    lastModified: new Date(post.date),
    changeFrequency: 'monthly' as const,
    priority: 0.6,
  }))

  return [
    ...staticPages.map(page => ({
      url: `${baseUrl}${page}`,
      lastModified: new Date(),
      changeFrequency: (page === '' ? 'weekly' : 'monthly') as 'weekly' | 'monthly',
      priority: page === '' ? 1.0 : page === '/features' ? 0.9 : 0.7,
    })),
    ...blogPages,
  ]
}
