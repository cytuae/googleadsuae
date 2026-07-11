/**
 * Security visit logger — Strict Security Gate v1
 * -----------------------------------------------
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
    console.log("[security:block]", {
      ip: payload.ip || info.ip || null,
      country: rules.country || info.country || null,
      asn: info.asn || null,
      company: info.company || null,
      vpn: info.is_vpn === true,
      proxy: info.is_proxy === true,
      tor: info.is_tor === true,
      relay: info.is_relay === true,
      hosting: info.is_hosting === true,
      blockReason: rules.reason || "blocked",
      matchedProvider: rules.matchedProvider || null,
      timestamp: payload.timestamp || new Date().toISOString(),
      requestId: payload.requestId || null,
      path: payload.path || null
    });
    return;
  }

  if (rules.reason === "google_bot_bypass") {
    console.log("[security:google-bot]", {
      ip: payload.ip || null,
      path: payload.path || null,
      timestamp: payload.timestamp || new Date().toISOString(),
      requestId: payload.requestId || null
    });
  }
}
