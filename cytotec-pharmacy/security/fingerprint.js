/**
 * Device Fingerprint Security Layer v1
 * ------------------------------------
 * Cookie / blacklist helpers for Edge middleware.
 * Client-side FingerprintJS runs in public/assets/js/fingerprint-security.js
 * and POSTs to /api/security/fingerprint.
 *
 * Add blocked visitorIds to: security/fingerprint-blacklist.json
 * (JSON array of exact FingerprintJS visitorId strings).
 */

import { isFingerprintBlacklisted } from "./blacklists";

export { isFingerprintBlacklisted, loadFingerprintBlacklist } from "./blacklists";

export const FINGERPRINT_COOKIE = "device_fingerprint";
export const SECURITY_BLOCKED_COOKIE = "security_blocked";

/**
 * @param {import('next/server').NextRequest} request
 * @returns {{ blocked: boolean, reason: string|null, visitorId: string|null }}
 */
export function evaluateFingerprintCookies(request) {
  try {
    const securityBlocked =
      request.cookies.get(SECURITY_BLOCKED_COOKIE)?.value || "";
    const visitorId =
      (request.cookies.get(FINGERPRINT_COOKIE)?.value || "").trim() || null;

    if (securityBlocked === "1") {
      return {
        blocked: true,
        reason: "device_fingerprint_blacklist",
        visitorId
      };
    }

    if (visitorId && isFingerprintBlacklisted(visitorId)) {
      return {
        blocked: true,
        reason: "device_fingerprint_blacklist",
        visitorId
      };
    }

    return { blocked: false, reason: null, visitorId };
  } catch {
    // Fail-open: never break the gate on cookie/parse errors
    return { blocked: false, reason: null, visitorId: null };
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
