/**
 * Known Google Search / Ads crawler detection
 * ------------------------------------------
 * Phase 1: User-Agent match only (no DNS verify on Edge).
 * These bots must never be blocked by country rules.
 */

/**
 * Googlebot, AdsBot, Mediapartners, InspectionTool, etc.
 * @see https://developers.google.com/search/docs/crawling-indexing/overview-google-crawlers
 */
const GOOGLE_BOT_UA =
  /(?:Googlebot|Google-InspectionTool|AdsBot-Google|Mediapartners-Google|APIs-Google|FeedFetcher-Google|Storebot-Google|GoogleOther|Google-Site-Verification|DuplexWeb-Google|Google-Read-Aloud|Google-Producer|Google-Safety)/i;

/**
 * @param {Request} request
 * @returns {boolean}
 */
export function isGoogleAdsOrSearchBot(request) {
  const ua = request.headers.get("user-agent") || "";
  if (!ua) return false;
  return GOOGLE_BOT_UA.test(ua);
}
