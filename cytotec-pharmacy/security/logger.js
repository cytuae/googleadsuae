/**
 * Security visit logger
 * ---------------------
 * Emits structured security events (Vercel / Edge console → production logs).
 */

/**
 * @typedef {Object} VisitLogPayload
 * @property {string} timestamp
 * @property {string} method
 * @property {string} path
 * @property {string} [ip]
 * @property {Object} [ipResult]
 * @property {Object} [fingerprintResult]
 * @property {Object} [rulesResult]
 * @property {string} [requestId]
 */

/**
 * @param {VisitLogPayload} payload
 * @param {{ config?: Object }} [context]
 * @returns {Promise<void>}
 */
export async function logVisit(payload, context = {}) {
  void context;

  if (typeof payload !== "object" || payload === null) {
    return;
  }

  const rules = payload.rulesResult || {};
  const info = payload.ipResult && payload.ipResult.info ? payload.ipResult.info : {};

  const event = {
    type: "security_visit",
    timestamp: payload.timestamp,
    requestId: payload.requestId,
    method: payload.method,
    path: payload.path,
    ip: payload.ip,
    decision: rules.decision || "allow",
    reason: rules.reason || null,
    country: rules.country || info.country || null,
    matchedRules: rules.matchedRules || [],
    blockType: rules.blockType || null
  };

  // Always log blocks; keep allow noise low unless needed later
  if (rules.decision === "block" || rules.reason === "blocked_country") {
    console.log("[security:block]", {
      reason: "blocked_country",
      country: event.country || "JO",
      requestId: event.requestId,
      ip: event.ip,
      path: event.path
    });
    return;
  }

  return;
}
