/**
 * Security visit logger (scaffold)
 * --------------------------------
 * Future: ship structured events to your SIEM, analytics, or edge KV.
 * Today: no-op (safe for production scaffolding).
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
 * Persist or emit a visit security event.
 * Must never throw into the request path in a way that breaks the site —
 * callers should still try/catch around this.
 *
 * @param {VisitLogPayload} payload
 * @param {{ config?: Object }} [context]
 * @returns {Promise<void>}
 */
export async function logVisit(payload, context = {}) {
  void context;

  // STAGE: logger — intentionally silent until a sink is configured
  // Example future sinks: console (dev), Vercel logs, HTTP webhook, KV, analytics
  if (typeof payload !== "object" || payload === null) {
    return;
  }

  return;
}
