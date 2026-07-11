/**
 * Security rules engine — Phase 1 + strict proxy
 * ----------------------------------------------
 * 1) Google bots → allow
 * 2) Known proxy → block (even AE/MA)
 * 3) Blocked countries → block
 * 4) Allowed countries (AE, MA) → allow
 * 5) Unknown country → allow (fail-open)
 * 6) Any other known country → block
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
  JORDAN: "JO",
  EGYPT: "EG",
  SYRIA: "SY",
  YEMEN: "YE",
  SUDAN: "SD",
  PAKISTAN: "PK",
  "UNITED ARAB EMIRATES": "AE",
  UAE: "AE",
  MOROCCO: "MA"
};

/**
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
 * @param {string[]} list
 * @returns {string[]}
 */
function normalizeCountryList(list) {
  if (!Array.isArray(list)) return [];
  return list
    .map((c) => String(c).toUpperCase())
    .filter((c) => /^[A-Z]{2}$/.test(c));
}

/**
 * @param {{
 *   request: Request,
 *   config?: Object,
 *   ipResult?: Object,
 *   fingerprintResult?: Object,
 *   isGoogleBot?: boolean
 * }} context
 * @returns {Promise<RulesResult>}
 */
export async function applyRules(context) {
  const config = context.config || {};
  const rulesConfig = config.rules || {};
  const country = resolveVisitorCountry(context.ipResult);

  const blockedCountries = normalizeCountryList(rulesConfig.blockedCountries);
  const allowedCountries = normalizeCountryList(rulesConfig.allowedCountries);
  const blockUnknownCountry = Boolean(rulesConfig.blockUnknownCountry);

  const info =
    context.ipResult && context.ipResult.info ? context.ipResult.info : null;

  // -------------------------------------------------------------------------
  // RULE: Google bot bypass (also short-circuited in middleware)
  // -------------------------------------------------------------------------
  if (context.isGoogleBot) {
    return {
      decision: "allow",
      allow: true,
      matchedRules: ["google_bot_bypass"],
      reason: "google_bot_bypass",
      country,
      blockType: null
    };
  }

  // -------------------------------------------------------------------------
  // RULE: strict proxy block (applies even inside AE/MA)
  // -------------------------------------------------------------------------
  if (rulesConfig.blockProxy && info && info.is_proxy === true) {
    return {
      decision: "block",
      allow: false,
      matchedRules: ["blocked_proxy"],
      reason: "blocked_proxy",
      country,
      blockType: "proxy"
    };
  }

  // -------------------------------------------------------------------------
  // RULE: explicit blocked countries
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

  // -------------------------------------------------------------------------
  // RULE: unknown country → fail-open (unless explicitly configured otherwise)
  // -------------------------------------------------------------------------
  if (!country) {
    if (blockUnknownCountry) {
      return {
        decision: "block",
        allow: false,
        matchedRules: ["unknown_country"],
        reason: "unknown_country",
        country: null,
        blockType: "country"
      };
    }

    return {
      decision: "allow",
      allow: true,
      matchedRules: ["unknown_country_fail_open"],
      reason: "unknown_country_fail_open",
      country: null,
      blockType: null
    };
  }

  // -------------------------------------------------------------------------
  // RULE: allowlist (AE, MA)
  // -------------------------------------------------------------------------
  if (allowedCountries.includes(country)) {
    return {
      decision: "allow",
      allow: true,
      matchedRules: ["allowed_country"],
      reason: "allowed_country",
      country,
      blockType: null
    };
  }

  // -------------------------------------------------------------------------
  // RULE: known country outside allowlist
  // -------------------------------------------------------------------------
  return {
    decision: "block",
    allow: false,
    matchedRules: ["country_not_allowed"],
    reason: "country_not_allowed",
    country,
    blockType: "country"
  };
}
