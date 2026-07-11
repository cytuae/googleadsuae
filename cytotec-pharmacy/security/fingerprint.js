/**
 * Device / browser fingerprint provider (scaffold)
 * ------------------------------------------------
 * Future: correlate stable visitor signals (headers, client hints, tokens).
 * Edge middleware cannot run browser JS — fingerprinting will typically
 * combine edge signals now + client-side token later.
 */

/**
 * @typedef {Object} FingerprintCheckResult
 * @property {boolean} ok
 * @property {boolean} allow - Always true until enforcement is enabled
 * @property {string} [fingerprintId]
 * @property {Object} [signals]
 * @property {string} [reason]
 */

/**
 * Evaluate fingerprint-related signals. Currently a no-op pass-through.
 *
 * @param {Request} request
 * @param {{ config?: Object, ipResult?: Object }} [context]
 * @returns {Promise<FingerprintCheckResult>}
 */
export async function checkFingerprint(request, context = {}) {
  void context;

  const signals = {
    userAgent: request.headers.get("user-agent") || "",
    acceptLanguage: request.headers.get("accept-language") || "",
    secChUa: request.headers.get("sec-ch-ua") || ""
  };

  // STAGE: fingerprint — placeholder only (no blocking, no persistence)
  return {
    ok: true,
    allow: true,
    fingerprintId: null,
    signals,
    reason: "fingerprint_not_implemented"
  };
}
