/** @type {import('next').NextConfig} */
const nextConfig = {
  transpilePackages: ['@anticlaude/engine'],
  images: {
    unoptimized: true,
  },
}

export default nextConfig
