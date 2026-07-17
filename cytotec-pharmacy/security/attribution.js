/**
 * Server-side ad attribution extraction.
 *
 * Blocked requests never reach the browser fingerprint script, so click IDs
 * must be captured from the original Edge request before the 403 response.
 */

const CLICK_ID_KEYS = ["gclid", "gbraid", "wbraid"];
const TRACKING_KEYS = [
  ...CLICK_ID_KEYS,
  "gad_source",
  "utm_source",
  "utm_medium",
  "utm_campaign",
  "utm_term",
  "utm_content"
];

/**
 * @param {unknown} value
 * @param {number} maxLength
 * @returns {string|null}
 */
function safeValue(value, maxLength = 256) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  return trimmed.slice(0, maxLength);
}

/**
 * @param {import('next/server').NextRequest} request
 */
export function extractAttribution(request) {
  const params = request.nextUrl.searchParams;
  /** @type {Record<string, string|null>} */
  const values = {};

  for (const key of TRACKING_KEYS) {
    values[key] = safeValue(params.get(key));
  }

  return {
    ...values,
    referrer: safeValue(request.headers.get("referer"), 512),
    userAgent: safeValue(request.headers.get("user-agent"), 512)
  };
}

/**
 * @param {ReturnType<typeof extractAttribution>|null|undefined} attribution
 * @returns {boolean}
 */
export function hasAdClickId(attribution) {
  if (!attribution) return false;
  return CLICK_ID_KEYS.some((key) => Boolean(attribution[key]));
}

/**
 * Returns one identifier for rate-window grouping without changing the
 * original fields kept in logs.
 * @param {ReturnType<typeof extractAttribution>|null|undefined} attribution
 * @returns {string|null}
 */
export function primaryClickId(attribution) {
  if (!attribution) return null;
  for (const key of CLICK_ID_KEYS) {
    if (attribution[key]) return attribution[key];
  }
  return null;
}
