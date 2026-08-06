/**
 * Trusted crawler / verifier detection
 * ------------------------------------
 * Google crawler UA + (AS15169 OR company Google LLC) → allow.
 * Hosting flag does NOT disqualify Google AS15169.
 * Spoofed Google UA alone is NOT enough when IPinfo is available.
 *
 * Broader Google crawler verification (IP ranges / DNS) lives in google-verify.js
 * and runs in middleware before blocked_hosting / country rules.
 */

import { normalizeAsn } from "./blacklists";
import {
  isAllowedGoogleCrawlerUserAgent,
  verifyGoogleCrawlerRequest
} from "./google-verify";

/** Google crawler User-Agents (candidates — still need network proof). */
const TRUSTED_GOOGLE_UA =
  /(?:AdsBot-Google-Mobile|AdsBot-Google|Googlebot|Google-InspectionTool|Storebot-Google|Mediapartners-Google|Google-Safety)/i;

/**
 * @param {Request} request
 * @returns {boolean}
 */
export function isGoogleAdsOrSearchBot(request) {
  return isAllowedGoogleCrawlerUserAgent(request);
}

/**
 * @param {string|null|undefined} asn
 * @param {string|null|undefined} company
 * @returns {boolean}
 */
export function isGoogleNetworkOrg(asn, company) {
  if (normalizeAsn(asn) === "15169") return true;
  if (company && /google\s*llc/i.test(String(company))) return true;
  return false;
}

/**
 * Verified Google crawler via IPinfo (before blocked_hosting / geo).
 * Requires Google crawler UA + (AS15169 OR Google LLC).
 *
 * @param {Request} request
 * @param {{ ok?: boolean, info?: { asn?: string|null, company?: string|null }|null }|null|undefined} [ipResult]
 * @returns {boolean}
 */
export function isTrustedSecurityBypassBot(request, ipResult) {
  const ua = request.headers.get("user-agent") || "";
  if (!ua || !TRUSTED_GOOGLE_UA.test(ua)) return false;

  // Spoofed UA alone is not enough when network enrichment exists
  if (!ipResult || ipResult.ok !== true || !ipResult.info) return false;

  const info = ipResult.info;
  if (!info.asn && !info.company) return false;

  return isGoogleNetworkOrg(info.asn, info.company);
}

export { verifyGoogleCrawlerRequest, isAllowedGoogleCrawlerUserAgent };
