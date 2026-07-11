/**
 * Security rules engine — Strict Security Gate v1 + geo allowlist
 * --------------------------------------------------------------
 * Order:
 * 1) Google bots → allow
 * 2) IPinfo failure → allow (fail-open, never 500)
 * 3) Strict gate: vpn | proxy | tor | relay | hosting
 * 4) Hosting/datacenter ASN–company keywords
 * 5) Geo blocklist / allowlist (existing behaviour)
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
 * @property {string|null} [matchedProvider]
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
 * @param {string|null|undefined} asn
 * @param {string|null|undefined} company
 * @param {string[]} keywords
 * @returns {{ matched: boolean, keyword: string|null }}
 */
export function matchHostingProvider(asn, company, keywords) {
  const haystack = `${asn || ""} ${company || ""}`.toLowerCase();
  if (!haystack.trim()) {
    return { matched: false, keyword: null };
  }

  const list = Array.isArray(keywords) ? keywords : [];
  for (let i = 0; i < list.length; i++) {
    const keyword = String(list[i] || "").trim();
    if (!keyword) continue;
    if (haystack.includes(keyword.toLowerCase())) {
      return { matched: true, keyword };
    }
  }

  return { matched: false, keyword: null };
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
  const ipResult = context.ipResult || {};
  const country = resolveVisitorCountry(ipResult);
  const info = ipResult.info || null;

  const blockedCountries = normalizeCountryList(rulesConfig.blockedCountries);
  const allowedCountries = normalizeCountryList(rulesConfig.allowedCountries);
  const blockUnknownCountry = Boolean(rulesConfig.blockUnknownCountry);

  // -------------------------------------------------------------------------
  // RULE: Google bot bypass (Ads / Search crawlers — keep Quality Score safe)
  // -------------------------------------------------------------------------
  if (context.isGoogleBot) {
    return {
      decision: "allow",
      allow: true,
      matchedRules: ["google_bot_bypass"],
      reason: "google_bot_bypass",
      country,
      blockType: null,
      matchedProvider: null
    };
  }

  // -------------------------------------------------------------------------
  // RULE: IPinfo failure → allow entire request (never 500 / never false-block)
  // -------------------------------------------------------------------------
  if (!ipResult.ok) {
    return {
      decision: "allow",
      allow: true,
      matchedRules: ["ipinfo_fail_open"],
      reason: "ipinfo_fail_open",
      country,
      blockType: null,
      matchedProvider: null
    };
  }

  // -------------------------------------------------------------------------
  // STRICT SECURITY GATE v1 — anonymity / hosting flags
  // -------------------------------------------------------------------------
  if (info) {
    if (rulesConfig.blockVpn && info.is_vpn === true) {
      return {
        decision: "block",
        allow: false,
        matchedRules: ["blocked_vpn"],
        reason: "blocked_vpn",
        country,
        blockType: "vpn",
        matchedProvider: null
      };
    }

    if (rulesConfig.blockProxy && info.is_proxy === true) {
      return {
        decision: "block",
        allow: false,
        matchedRules: ["blocked_proxy"],
        reason: "blocked_proxy",
        country,
        blockType: "proxy",
        matchedProvider: null
      };
    }

    if (rulesConfig.blockTor && info.is_tor === true) {
      return {
        decision: "block",
        allow: false,
        matchedRules: ["blocked_tor"],
        reason: "blocked_tor",
        country,
        blockType: "tor",
        matchedProvider: null
      };
    }

    if (rulesConfig.blockRelay && info.is_relay === true) {
      return {
        decision: "block",
        allow: false,
        matchedRules: ["blocked_relay"],
        reason: "blocked_relay",
        country,
        blockType: "relay",
        matchedProvider: null
      };
    }

    if (rulesConfig.blockHosting && info.is_hosting === true) {
      return {
        decision: "block",
        allow: false,
        matchedRules: ["blocked_hosting"],
        reason: "blocked_hosting",
        country,
        blockType: "hosting",
        matchedProvider: null
      };
    }

    // -----------------------------------------------------------------------
    // Hosting / datacenter provider keywords (ASN + company)
    // -----------------------------------------------------------------------
    if (rulesConfig.blockHostingProviders) {
      const providerHit = matchHostingProvider(
        info.asn,
        info.company,
        rulesConfig.hostingProviderKeywords || []
      );

      if (providerHit.matched) {
        return {
          decision: "block",
          allow: false,
          matchedRules: ["blocked_hosting_provider"],
          reason: "blocked_hosting_provider",
          country,
          blockType: "hosting_provider",
          matchedProvider: providerHit.keyword
        };
      }
    }
  }

  // -------------------------------------------------------------------------
  // Geo: explicit blocked countries
  // -------------------------------------------------------------------------
  if (country && blockedCountries.includes(country)) {
    return {
      decision: "block",
      allow: false,
      matchedRules: ["blocked_country"],
      reason: "blocked_country",
      country,
      blockType: "country",
      matchedProvider: null
    };
  }

  // -------------------------------------------------------------------------
  // Geo: unknown country → fail-open
  // -------------------------------------------------------------------------
  if (!country) {
    if (blockUnknownCountry) {
      return {
        decision: "block",
        allow: false,
        matchedRules: ["unknown_country"],
        reason: "unknown_country",
        country: null,
        blockType: "country",
        matchedProvider: null
      };
    }

    return {
      decision: "allow",
      allow: true,
      matchedRules: ["unknown_country_fail_open"],
      reason: "unknown_country_fail_open",
      country: null,
      blockType: null,
      matchedProvider: null
    };
  }

  // -------------------------------------------------------------------------
  // Geo: allowlist (AE, MA)
  // -------------------------------------------------------------------------
  if (allowedCountries.includes(country)) {
    return {
      decision: "allow",
      allow: true,
      matchedRules: ["allowed_country"],
      reason: "allowed_country",
      country,
      blockType: null,
      matchedProvider: null
    };
  }

  return {
    decision: "block",
    allow: false,
    matchedRules: ["country_not_allowed"],
    reason: "country_not_allowed",
    country,
    blockType: "country",
    matchedProvider: null
  };
}
