/** @type {import('next').NextConfig} */
const nextConfig = {
  distDir: process.env.NEXT_DIST_DIR || '.next',
  turbopack: {
    root: process.env.NEXT_WORKSPACE_ROOT || `${process.cwd()}/../..`,
  },
  allowedDevOrigins: ['127.0.0.1', 'localhost'],
  reactStrictMode: true,
  skipTrailingSlashRedirect: true,
  compress: true,
  poweredByHeader: false,
  compiler: {
    removeConsole: process.env.NODE_ENV === 'production' ? { exclude: ['error'] } : false,
  },
  experimental: {
    optimizePackageImports: ['lucide-react', 'framer-motion', '@tanstack/react-query', 'd3'],
  },
  async headers() {
    return [
      {
        source: '/api/(.*)',
        headers: [{ key: 'Cache-Control', value: 'no-store' }],
      },
    ]
  },
}

if (process.env.NEXT_OUTPUT === 'standalone') {
  nextConfig.output = 'standalone'
}

module.exports = nextConfig
