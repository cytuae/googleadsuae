/**
 * Trusted crawler / verifier detection
 * ------------------------------------
 * Google Ads/Search bots + Statcounter (and similar) install verifiers.
 * Edge: User-Agent + path heuristics only (no DNS verify).
 */

/**
 * @see https://developers.google.com/search/docs/crawling-indexing/overview-google-crawlers
 */
const GOOGLE_BOT_UA =
  /(?:Googlebot|Google-InspectionTool|AdsBot-Google|Mediapartners-Google|APIs-Google|FeedFetcher-Google|Storebot-Google|GoogleOther|Google-Site-Verification|DuplexWeb-Google|Google-Read-Aloud|Google-Producer|Google-Safety)/i;

const STATCOUNTER_UA = /statcounter/i;

/** Non-browser clients often used by Statcounter "Verify Installation" */
const SCRIPT_VERIFIER_UA =
  /(?:python-requests|python-urllib|curl\/|wget\/|Go-http-client|axios\/|node-fetch|Scrapy|Java\/|Apache-HttpClient|libwww-perl|http\.rb|Faraday)/i;

/**
 * @param {Request} request
 * @returns {string}
 */
function getPathname(request) {
  try {
    return new URL(request.url).pathname || "/";
  } catch {
    return "/";
  }
}

/**
 * @param {Request} request
 * @returns {boolean}
 */
export function isGoogleAdsOrSearchBot(request) {
  const ua = request.headers.get("user-agent") || "";
  if (!ua) return false;
  return GOOGLE_BOT_UA.test(ua);
}

/**
 * @param {Request} request
 * @returns {boolean}
 */
export function isStatCounterBot(request) {
  const ua = request.headers.get("user-agent") || "";
  if (!ua) return false;
  return STATCOUNTER_UA.test(ua);
}

/**
 * Statcounter dashboard verify often fetches / from a datacenter with a
 * non-browser User-Agent. Allow only on HTML entry paths.
 *
 * @param {Request} request
 * @returns {boolean}
 */
export function isInstallVerifierClient(request) {
  const path = getPathname(request);
  if (path !== "/" && path !== "/index.html") return false;

  const ua = request.headers.get("user-agent") || "";
  if (!ua) return false;
  if (STATCOUNTER_UA.test(ua)) return true;

  // Real browsers always include Mozilla/AppleWebKit — skip those
  if (/Mozilla\/|AppleWebKit\/|Chrome\/|Safari\/|Firefox\//i.test(ua)) {
    return false;
  }

  return SCRIPT_VERIFIER_UA.test(ua);
}

/**
 * Simple server-side fetch signature (Statcounter verify / uptime checks).
 * Real browsers send sec-ch-ua + accept-language on navigate.
 *
 * @param {Request} request
 * @returns {boolean}
 */
export function isSimpleServerFetch(request) {
  const path = getPathname(request);
  if (path !== "/" && path !== "/index.html") return false;

  if (request.headers.get("sec-ch-ua")) return false;
  if (request.headers.get("sec-fetch-mode") === "navigate") return false;

  const ua = request.headers.get("user-agent") || "";
  const acceptLanguage = request.headers.get("accept-language");

  if (STATCOUNTER_UA.test(ua)) return true;
  if (SCRIPT_VERIFIER_UA.test(ua)) return true;

  // No Accept-Language + no Mozilla → almost certainly not a real visitor browser
  if (!acceptLanguage && ua && !/Mozilla\//i.test(ua)) return true;

  return false;
}

/**
 * Bots that must never be geo/hosting-blocked.
 * @param {Request} request
 * @returns {boolean}
 */
export function isTrustedSecurityBypassBot(request) {
  return (
    isGoogleAdsOrSearchBot(request) ||
    isStatCounterBot(request) ||
    isInstallVerifierClient(request) ||
    isSimpleServerFetch(request)
  );
}
