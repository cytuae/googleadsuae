/** @type {import('next').NextConfig} */
const nextConfig = {
  // Serve the static landing page without Edge middleware.
  async rewrites() {
    return [
      {
        source: "/",
        destination: "/index.html"
      }
    ];
  }
};

module.exports = nextConfig;
