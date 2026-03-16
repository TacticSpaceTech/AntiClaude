import type { Metadata } from 'next'
import { Analytics } from '@vercel/analytics/next'
import './globals.css'

export const metadata: Metadata = {
  metadataBase: new URL('https://anticlaude.dev'),
  title: {
    default: 'AntiClaude — Open-Source AI Agent Security Scanner',
    template: '%s | AntiClaude',
  },
  description: 'Red-team your AI agents from the terminal. 64 attack payloads covering 7/10 OWASP Agentic Top 10 categories. npm-native, open-source, LLM Judge, MCP Scanner.',
  icons: {
    icon: [
      { url: '/favicon.ico', sizes: '48x48' },
      { url: '/icon-192x192.png', sizes: '192x192', type: 'image/png' },
      { url: '/icon-512x512.png', sizes: '512x512', type: 'image/png' },
    ],
    apple: { url: '/apple-icon.png', sizes: '180x180' },
  },
  openGraph: {
    type: 'website',
    siteName: 'AntiClaude',
    title: 'AntiClaude — Open-Source AI Agent Security Scanner',
    description: 'Red-team your AI agents from the terminal. 64 attack payloads, 7 OWASP categories, LLM Judge, MCP Scanner.',
    images: [{ url: '/og-image.png', width: 1200, height: 630, alt: 'AntiClaude - AI Agent Security Scanner' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'AntiClaude — Open-Source AI Agent Security Scanner',
    description: 'Red-team your AI agents from the terminal. 64 attack payloads, 7 OWASP categories.',
    images: ['/og-image.png'],
  },
  robots: { index: true, follow: true },
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en">
      <body className="font-sans antialiased">
        {children}
        <Analytics />
      </body>
    </html>
  )
}
