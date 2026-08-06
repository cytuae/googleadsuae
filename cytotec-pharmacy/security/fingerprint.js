/**
 * Device Fingerprint Security Layer v1
 * ------------------------------------
 * Cookie / denylist helpers for Edge middleware (monitor-only).
 * Blacklisted visitorIds never cause HTTP 403 — only logging.
 *
 * Add monitored visitorIds to: security/fingerprint-blacklist.json
 */

import { isFingerprintBlacklisted } from "./blacklists";

export { isFingerprintBlacklisted, loadFingerprintBlacklist } from "./blacklists";

export const FINGERPRINT_COOKIE = "device_fingerprint";
export const SECURITY_BLOCKED_COOKIE = "security_blocked";

/**
 * Cookie / blacklist signal only — does not decide monitor vs hard (needs IPinfo).
 *
 * @param {import('next/server').NextRequest} request
 * @returns {{
 *   suspicious: boolean,
 *   blocked: boolean,
 *   reason: string|null,
 *   visitorId: string|null
 * }}
 */
export function evaluateFingerprintCookies(request) {
  try {
    const securityBlocked =
      request.cookies.get(SECURITY_BLOCKED_COOKIE)?.value || "";
    const visitorId =
      (request.cookies.get(FINGERPRINT_COOKIE)?.value || "").trim() || null;

    if (securityBlocked === "1") {
      return {
        suspicious: true,
        blocked: true,
        reason: "blocked_visitor_id",
        visitorId
      };
    }

    if (visitorId && isFingerprintBlacklisted(visitorId)) {
      return {
        suspicious: true,
        blocked: true,
        reason: "blocked_visitor_id",
        visitorId
      };
    }

    return { suspicious: false, blocked: false, reason: null, visitorId };
  } catch {
    // Fail-open: never break the gate on cookie/parse errors
    return {
      suspicious: false,
      blocked: false,
      reason: null,
      visitorId: null
    };
  }
}

/**
 * Legacy scaffold — Edge cannot run FingerprintJS; cookies are the signal.
 *
 * @param {Request} request
 * @param {{ config?: Object, ipResult?: Object }} [context]
 * @returns {Promise<{ ok: boolean, allow: boolean, fingerprintId: string|null, reason: string }>}
 */
export async function checkFingerprint(request, context = {}) {
  void context;
  const result = evaluateFingerprintCookies(
    /** @type {import('next/server').NextRequest} */ (request)
  );

  return {
    ok: true,
    allow: !result.blocked,
    fingerprintId: result.visitorId,
    reason: result.reason || "fingerprint_cookie_ok"
  };
}
