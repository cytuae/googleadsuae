/**
 * Minimal App Router shell so Next.js / Vercel can build.
 * The real landing page is served from /public/index.html via middleware rewrite.
 */
export const metadata = {
  title: "د. عهود توفيق | استشارة نساء وتوليد",
  description: "استشارة نسائية خاصة عبر واتساب",
  alternates: {
    types: {
      "application/rss+xml": "https://www.cytotec.ae/feed.xml"
    }
  }
};

export default function RootLayout({ children }) {
  return (
    <html lang="ar" dir="rtl">
      <head>
        <link
          rel="alternate"
          type="application/rss+xml"
          title="سايتوتك الإمارات — RSS"
          href="https://www.cytotec.ae/feed.xml"
        />
      </head>
      <body>{children}</body>
    </html>
  );
}
