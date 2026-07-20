/**
 * Dynamic RSS endpoint — /feed.xml
 * Reads content/articles.json so the feed stays in sync after deploy.
 * Static public/feed.xml is also generated on prebuild for static hosts.
 */

import { NextResponse } from "next/server";
import { readFile } from "node:fs/promises";
import path from "node:path";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const SITE_ORIGIN = "https://www.cytotec.ae";

/**
 * @param {string} value
 * @returns {string}
 */
function escapeXml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/**
 * @param {string} iso
 * @returns {string}
 */
function toRfc822(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return new Date().toUTCString();
  return d.toUTCString();
}

/**
 * @param {string} p
 * @returns {string}
 */
function absoluteUrl(p) {
  if (!p) return `${SITE_ORIGIN}/`;
  if (/^https?:\/\//i.test(p)) return p;
  const normalized = p.startsWith("/") ? p : `/${p}`;
  return `${SITE_ORIGIN}${normalized}`;
}

/**
 * @param {any} data
 * @returns {string}
 */
function buildFeed(data) {
  const site = data.site || {};
  const articles = Array.isArray(data.articles) ? [...data.articles] : [];
  articles.sort(
    (a, b) =>
      new Date(b.publishedAt).getTime() - new Date(a.publishedAt).getTime()
  );

  const lastBuild = articles[0]?.publishedAt
    ? toRfc822(articles[0].publishedAt)
    : new Date().toUTCString();

  const items = articles
    .map((article) => {
      const link = absoluteUrl(article.path || article.url || "");
      const guid = article.id
        ? `urn:cytotec-ae:article:${article.id}`
        : link;
      return `    <item>
      <title>${escapeXml(article.title || "Untitled")}</title>
      <link>${escapeXml(link)}</link>
      <guid isPermaLink="false">${escapeXml(guid)}</guid>
      <description>${escapeXml(article.description || "")}</description>
      <pubDate>${toRfc822(article.publishedAt || new Date().toISOString())}</pubDate>
    </item>`;
    })
    .join("\n");

  return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>${escapeXml(site.title || "Cytotec.ae Articles")}</title>
    <link>${escapeXml(site.link || `${SITE_ORIGIN}/`)}</link>
    <description>${escapeXml(site.description || "")}</description>
    <language>${escapeXml(site.language || "ar")}</language>
    <lastBuildDate>${lastBuild}</lastBuildDate>
    <atom:link href="${SITE_ORIGIN}/feed.xml" rel="self" type="application/rss+xml" />
${items}
  </channel>
</rss>
`;
}

export async function GET() {
  try {
    const filePath = path.join(process.cwd(), "content", "articles.json");
    const raw = await readFile(filePath, "utf8");
    const data = JSON.parse(raw);
    const xml = buildFeed(data);

    return new NextResponse(xml, {
      status: 200,
      headers: {
        "content-type": "application/rss+xml; charset=utf-8",
        "cache-control": "public, s-maxage=600, stale-while-revalidate=86400"
      }
    });
  } catch (error) {
    // Fail-safe: never 500 for feed consumers
    const fallback = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Cytotec.ae</title>
    <link>${SITE_ORIGIN}/</link>
    <description>Feed temporarily unavailable</description>
  </channel>
</rss>
`;
    return new NextResponse(fallback, {
      status: 200,
      headers: { "content-type": "application/rss+xml; charset=utf-8" }
    });
  }
}
