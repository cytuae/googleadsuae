/**
 * Visitor fingerprint block mode
 * ------------------------------
 * VISITOR_BLOCK_MODE=monitor (default) | hard
 *
 * monitor: blacklisted visitorIds on UAE residential IPs are flagged
 *          and allowed (page + WhatsApp). Hard 403 elsewhere.
 * hard:    blacklisted visitorIds always get HTTP 403.
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
 * @returns {VisitorBlockMode}
 */
export function getVisitorBlockMode() {
  const raw = String(process.env.VISITOR_BLOCK_MODE || "monitor")
    .trim()
    .toLowerCase();
  return raw === "hard" ? "hard" : "monitor";
}

/**
 * UAE residential = AE country and not VPN/proxy/TOR/relay/hosting.
 *
 * @param {{ country?: string|null, is_vpn?: boolean|null, is_proxy?: boolean|null, is_tor?: boolean|null, is_relay?: boolean|null, is_hosting?: boolean|null }|null|undefined} info
 * @returns {boolean}
 */
export function isUaeResidential(info) {
  if (!info || typeof info !== "object") return false;
  const country = asCountryCode(info.country);
  if (country !== "AE") return false;
  if (info.is_vpn === true) return false;
  if (info.is_proxy === true) return false;
  if (info.is_tor === true) return false;
  if (info.is_relay === true) return false;
  if (info.is_hosting === true) return false;
  return true;
}

/**
 * Decide hard-block vs monitor-only for a blacklisted / security_blocked visitor.
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
  const mode = opts.mode || getVisitorBlockMode();
  const visitorId =
    typeof opts.visitorId === "string" && opts.visitorId.trim()
      ? opts.visitorId.trim()
      : null;
  const ipInfo = opts.ipInfo || null;

  if (mode === "hard") {
    return {
      hardBlock: true,
      monitorOnly: false,
      reason: "blocked_visitor_id",
      flagged: false,
      visitorId
    };
  }

  // monitor mode — UAE residential: allow + flag
  if (isUaeResidential(ipInfo)) {
    return {
      hardBlock: false,
      monitorOnly: true,
      reason: "monitored_suspicious_visitor",
      flagged: true,
      visitorId
    };
  }

  // monitor mode but not UAE residential → keep hard 403
  return {
    hardBlock: true,
    monitorOnly: false,
    reason: "blocked_visitor_id",
    flagged: false,
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
