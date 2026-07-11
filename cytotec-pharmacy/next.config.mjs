/** @type {import('next').NextConfig} */
const nextConfig = {
  // Serve the existing static landing experience while enabling Edge Middleware.
  // Additional App Router pages can be added later without changing the security pipeline.
  async rewrites() {
    return [];
  }
};

export default nextConfig;
