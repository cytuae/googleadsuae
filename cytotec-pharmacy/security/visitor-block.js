/**
 * Visitor fingerprint monitoring
 * ------------------------------
 * Blacklisted visitorIds are NEVER hard-blocked (no HTTP 403).
 * Always monitor-only → monitored_suspicious_visitor.
 *
 * VISITOR_BLOCK_MODE env is ignored for enforcement (legacy; kept for logs).
 */

/** @typedef {'monitor' | 'hard'} VisitorBlockMode */

/**
 * @param {unknown} value
 * @returns {string|null}
 */
function asCountryCode(value) {
  if (typeof value !== "string") return null;
  const upper = value.trim().toUpperCase();
  if (/^[A-Z]{2}$/.test(upper)) return upper;
  if (upper === "UAE" || upper === "UNITED ARAB EMIRATES") return "AE";
  return null;
}

/**
 * Legacy env reader — enforcement always monitor-only now.
 * @returns {VisitorBlockMode}
 */
export function getVisitorBlockMode() {
  const raw = String(process.env.VISITOR_BLOCK_MODE || "monitor")
    .trim()
    .toLowerCase();
  return raw === "hard" ? "hard" : "monitor";
}

/**
 * UAE visitor (any network type) — country AE.
 * @param {{ country?: string|null }|null|undefined} info
 * @returns {boolean}
 */
export function isUaeCountry(info) {
  if (!info || typeof info !== "object") return false;
  return asCountryCode(info.country) === "AE";
}

/**
 * @deprecated Prefer isUaeCountry — AE is always allowed even on VPN/hosting.
 */
export function isUaeResidential(info) {
  return isUaeCountry(info);
}

/**
 * Suspicious visitorId decision — always monitor-only (never hard 403).
 *
 * @param {{
 *   mode?: VisitorBlockMode,
 *   ipInfo?: Object|null,
 *   visitorId?: string|null
 * }} opts
 * @returns {{
 *   hardBlock: boolean,
 *   monitorOnly: boolean,
 *   reason: string,
 *   flagged: boolean,
 *   visitorId: string|null
 * }}
 */
export function resolveSuspiciousVisitorDecision(opts = {}) {
  const visitorId =
    typeof opts.visitorId === "string" && opts.visitorId.trim()
      ? opts.visitorId.trim()
      : null;

  // Fingerprints are monitor-only worldwide — never HTTP 403 for visitorId.
  void opts.mode;
  void opts.ipInfo;

  return {
    hardBlock: false,
    monitorOnly: true,
    reason: "monitored_suspicious_visitor",
    flagged: true,
    visitorId
  };
}

/**
 * Digits-only international WhatsApp number (no + / spaces).
 * @param {unknown} raw
 * @returns {string}
 */
export function normalizeWhatsAppDigits(raw) {
  return String(raw || "").replace(/\D/g, "");
}

/**
 * @param {string} phoneDigits
 * @param {string} [text]
 * @returns {string}
 */
export function buildWhatsAppUrl(phoneDigits, text) {
  const phone = normalizeWhatsAppDigits(phoneDigits);
  const msg = encodeURIComponent(text || "");
  return `https://wa.me/${phone}?text=${msg}`;
}
