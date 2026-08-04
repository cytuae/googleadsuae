/**
 * Trusted crawler / verifier detection
 * ------------------------------------
 * trusted Google bypass (IPinfo path):
 *   Googlebot/AdsBot UA + ASN AS15169 + company Google LLC
 * Hosting flag does NOT disqualify Google AS15169 (crawlers are datacenter).
 * Other hosting providers never receive this bypass.
 *
 * Broader Google crawler verification (IP ranges / DNS) lives in google-verify.js
 * and runs in middleware before blocked_hosting.
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
 * Verified Google crawler via IPinfo signals (before blocked_hosting).
 * Requires Google UA + AS15169 + Google LLC. Empty ASN/company → no bypass.
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

  // Google crawlers only — never grant to other hosting ASNs
  if (normalizeAsn(asn) !== "15169") return false;
  if (!/google\s*llc/i.test(String(company))) return false;

  return true;
}

export { verifyGoogleCrawlerRequest, isAllowedGoogleCrawlerUserAgent };
