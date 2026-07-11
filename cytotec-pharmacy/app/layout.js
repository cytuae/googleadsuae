/**
 * Minimal App Router shell so Next.js / Vercel can build.
 * The real landing page is served from /public/index.html via middleware rewrite.
 */
export const metadata = {
  title: "د. عهود توفيق | استشارة نساء وتوليد",
  description: "استشارة نسائية خاصة عبر واتساب"
};

export default function RootLayout({ children }) {
  return (
    <html lang="ar" dir="rtl">
      <body>{children}</body>
    </html>
  );
}
