/**
 * Minimal App Router shell so Next.js / Vercel can build.
 * The real landing page is served from /public/index.html via middleware rewrite.
 * Google Tag (GA4) loads globally for all Next.js routes via next/script.
 * Landing HTML already includes the same tag once in public/index.html (no double-load on that path).
 */
import Script from "next/script";

export const metadata = {
  title: "د. عهود توفيق | استشارة نساء وتوليد",
  description: "استشارة نسائية خاصة عبر واتساب"
};

const GA_MEASUREMENT_ID = "G-VDB33PME30";

export default function RootLayout({ children }) {
  return (
    <html lang="ar" dir="rtl">
      <body>
        <Script
          src={`https://www.googletagmanager.com/gtag/js?id=${GA_MEASUREMENT_ID}`}
          strategy="afterInteractive"
        />
        <Script id="google-tag-gtag" strategy="afterInteractive">
          {`
            window.dataLayer = window.dataLayer || [];
            function gtag(){dataLayer.push(arguments);}
            gtag('js', new Date());
            gtag('config', '${GA_MEASUREMENT_ID}');
          `}
        </Script>
        {children}
      </body>
    </html>
  );
}
