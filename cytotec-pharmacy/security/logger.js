/**
 * Security visit logger
 * ---------------------
 * Structured events for Vercel Edge / production logs.
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
      reason: rules.reason || "blocked",
      country: rules.country || info.country || null,
      requestId: payload.requestId,
      ip: payload.ip,
      path: payload.path,
      matchedRules: rules.matchedRules || []
    });
    return;
  }

  if (rules.reason === "google_bot_bypass") {
    console.log("[security:google-bot]", {
      requestId: payload.requestId,
      path: payload.path,
      country: rules.country || null
    });
  }
}
