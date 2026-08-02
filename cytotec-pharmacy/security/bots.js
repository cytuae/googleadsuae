/**
 * Trusted crawler / verifier detection
 * ------------------------------------
 * trusted_bot_bypass is strict:
 *   ASN AS15169 + company Google LLC + Googlebot/AdsBot UA
 * Empty IPinfo / hosting traffic never receives trusted_bot_bypass.
 *
 * Broader Google crawler verification (IP ranges / DNS) lives in google-verify.js.
 */

import { normalizeAsn } from "./blacklists";
import {
  isAllowedGoogleCrawlerUserAgent,
  verifyGoogleCrawlerRequest
} from "./google-verify";

/** UA must be Googlebot or AdsBot (desktop/mobile). */
const TRUSTED_GOOGLE_UA =
  /(?:AdsBot-Google-Mobile|AdsBot-Google|Googlebot)/i;

/**
 * @param {Request} request
 * @returns {boolean}
 */
export function isGoogleAdsOrSearchBot(request) {
  return isAllowedGoogleCrawlerUserAgent(request);
}

/**
 * Strict trusted_bot_bypass — requires verified IPinfo signals.
 * Never grants bypass for empty ASN/company or hosting-classified IPs.
 *
 * @param {Request} request
 * @param {{ ok?: boolean, info?: { asn?: string|null, company?: string|null, is_hosting?: boolean|null }|null }|null|undefined} [ipResult]
 * @returns {boolean}
 */
export function isTrustedSecurityBypassBot(request, ipResult) {
  const ua = request.headers.get("user-agent") || "";
  if (!ua || !TRUSTED_GOOGLE_UA.test(ua)) return false;

  if (!ipResult || ipResult.ok !== true || !ipResult.info) return false;

  const info = ipResult.info;
  const asn = info.asn;
  const company = info.company;

  // Empty IPinfo data → no bypass
  if (!asn || !company) return false;

  // Hosting-classified traffic → no bypass (Google crawlers use AS15169 path / verify)
  if (info.is_hosting === true) return false;

  if (normalizeAsn(asn) !== "15169") return false;
  if (!/google\s*llc/i.test(String(company))) return false;

  return true;
}

export { verifyGoogleCrawlerRequest, isAllowedGoogleCrawlerUserAgent };
