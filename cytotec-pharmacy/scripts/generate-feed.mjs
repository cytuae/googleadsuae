/**
 * Generate public/feed.xml from content/articles.json
 * --------------------------------------------------
 * Add new articles in content/articles.json only.
 * This script runs on `prebuild` / `npm run feed` and regenerates the RSS file.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");
const articlesPath = path.join(root, "content", "articles.json");
const outPath = path.join(root, "public", "feed.xml");

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
  if (Number.isNaN(d.getTime())) {
    return new Date().toUTCString();
  }
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

function buildFeed(data) {
  const site = data.site || {};
  const articles = Array.isArray(data.articles) ? [...data.articles] : [];

  articles.sort((a, b) => {
    return new Date(b.publishedAt).getTime() - new Date(a.publishedAt).getTime();
  });

  const channelTitle = site.title || "Cytotec.ae Articles";
  const channelLink = site.link || `${SITE_ORIGIN}/`;
  const channelDesc =
    site.description || "Articles and medical information from Cytotec.ae";
  const language = site.language || "ar";
  const lastBuild = articles[0]?.publishedAt
    ? toRfc822(articles[0].publishedAt)
    : new Date().toUTCString();

  const items = articles
    .map((article) => {
      const link = absoluteUrl(article.path || article.url || "");
      const guid = article.id
        ? `urn:cytotec-ae:article:${article.id}`
        : link;
      const title = escapeXml(article.title || "Untitled");
      const description = escapeXml(article.description || "");
      const pubDate = toRfc822(article.publishedAt || new Date().toISOString());

      return `    <item>
      <title>${title}</title>
      <link>${escapeXml(link)}</link>
      <guid isPermaLink="false">${escapeXml(guid)}</guid>
      <description>${description}</description>
      <pubDate>${pubDate}</pubDate>
    </item>`;
    })
    .join("\n");

  return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>${escapeXml(channelTitle)}</title>
    <link>${escapeXml(channelLink)}</link>
    <description>${escapeXml(channelDesc)}</description>
    <language>${escapeXml(language)}</language>
    <lastBuildDate>${lastBuild}</lastBuildDate>
    <atom:link href="${SITE_ORIGIN}/feed.xml" rel="self" type="application/rss+xml" />
${items}
  </channel>
</rss>
`;
}

function main() {
  if (!fs.existsSync(articlesPath)) {
    console.error(`[feed] missing ${articlesPath}`);
    process.exit(1);
  }

  const raw = fs.readFileSync(articlesPath, "utf8");
  const data = JSON.parse(raw);
  const xml = buildFeed(data);

  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, xml, "utf8");
  console.log(
    `[feed] wrote ${outPath} (${(data.articles || []).length} articles)`
  );
}

main();
