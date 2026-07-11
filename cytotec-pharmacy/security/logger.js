/**
 * Security visit logger — blocked requests as structured JSON
 * ----------------------------------------------------------
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
        IP: payload.ip || info.ip || null,
        pathname: payload.path || null,
        country: rules.country || info.country || null,
        ASN: info.asn || null,
        company: info.company || null,
        vpn: info.is_vpn === true,
        proxy: info.is_proxy === true,
        tor: info.is_tor === true,
        relay: info.is_relay === true,
        hosting: info.is_hosting === true,
        blockReason: rules.reason || "blocked"
      })
    );
    return;
  }

  if (rules.reason === "google_bot_bypass") {
    console.log(
      JSON.stringify({
        timestamp: payload.timestamp || new Date().toISOString(),
        IP: payload.ip || null,
        pathname: payload.path || null,
        event: "google_bot_bypass"
      })
    );
  }
}
