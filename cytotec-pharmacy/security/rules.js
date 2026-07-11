/**
 * Security rules engine
 * ---------------------
 * Combines provider results into allow | challenge | block decisions.
 *
 * Active rules:
 *   - Block ISO country JO (Jordan)
 *
 * Disabled for now:
 *   - VPN / Proxy / Relay / Hosting detection
 */

/**
 * @typedef {'allow' | 'challenge' | 'block'} RuleDecision
 *
 * @typedef {Object} RulesResult
 * @property {RuleDecision} decision
 * @property {boolean} allow
 * @property {string[]} matchedRules
 * @property {string} [reason]
 * @property {string|null} [country]
 * @property {string} [blockType]
 */

const COUNTRY_NAME_TO_CODE = {
  JORDAN: "JO"
};

/**
 * Normalize IPinfo country field to ISO 3166-1 alpha-2 when possible.
 * @param {unknown} value
 * @returns {string|null}
 */
export function normalizeCountryCode(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed) return null;

  const upper = trimmed.toUpperCase();
  if (/^[A-Z]{2}$/.test(upper)) return upper;

  return COUNTRY_NAME_TO_CODE[upper] || null;
}

/**
 * @param {Object|null|undefined} ipResult
 * @returns {string|null}
 */
function resolveVisitorCountry(ipResult) {
  const info = ipResult && ipResult.info ? ipResult.info : null;
  if (!info) return null;
  return normalizeCountryCode(info.country);
}

/**
 * Apply security rules to aggregated provider results.
 *
 * @param {{
 *   request: Request,
 *   config?: Object,
 *   ipResult?: Object,
 *   fingerprintResult?: Object
 * }} context
 * @returns {Promise<RulesResult>}
 */
export async function applyRules(context) {
  const config = context.config || {};
  const rulesConfig = config.rules || {};
  const blockedCountries = Array.isArray(rulesConfig.blockedCountries)
    ? rulesConfig.blockedCountries.map((c) => String(c).toUpperCase())
    : [];

  const country = resolveVisitorCountry(context.ipResult);

  // -------------------------------------------------------------------------
  // RULE: blocked country (JO)
  // -------------------------------------------------------------------------
  if (country && blockedCountries.includes(country)) {
    return {
      decision: "block",
      allow: false,
      matchedRules: ["blocked_country"],
      reason: "blocked_country",
      country,
      blockType: "country"
    };
  }

  // VPN / Proxy / Relay / Hosting — intentionally not evaluated yet
  // (rulesConfig.blockVpn | blockProxy | blockRelay | blockHosting remain false)

  return {
    decision: "allow",
    allow: true,
    matchedRules: [],
    reason: "default_allow",
    country,
    blockType: null
  };
}
