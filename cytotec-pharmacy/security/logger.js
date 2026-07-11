/**
 * Security visit logger — Security Layer v2
 * ----------------------------------------
 * Logs blocked visits as:
 * { timestamp, ip, provider, company, asn, country, reason }
 *
 * Never logs secrets (IPINFO_TOKEN).
 */

/**
 * @param {Object} payload
 * @param {{ config?: Object }} [context]
 * @returns {Promise<void>}
 */
export async function logVisit(payload, context = {}) {
  void context;

  if (typeof payload !== "object" || payload === null) {
    return;
  }

  const rules = payload.rulesResult || {};
  const info =
    payload.ipResult && payload.ipResult.info ? payload.ipResult.info : {};

  if (rules.decision === "block") {
    console.log(
      JSON.stringify({
        timestamp: payload.timestamp || new Date().toISOString(),
        ip: payload.ip || info.ip || null,
        provider:
          rules.matchedProvider ||
          info.privacy_service ||
          info.provider ||
          null,
        company: info.company || null,
        asn: info.asn || null,
        country: rules.country || info.country || null,
        reason: rules.reason || "blocked"
      })
    );
    return;
  }

  if (
    rules.reason === "google_bot_bypass" ||
    rules.reason === "trusted_bot_bypass"
  ) {
    console.log(
      JSON.stringify({
        timestamp: payload.timestamp || new Date().toISOString(),
        ip: payload.ip || null,
        provider: null,
        company: null,
        asn: null,
        country: null,
        reason: rules.reason
      })
    );
  }
}
