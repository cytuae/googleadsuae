/**
 * Security rules engine — Security Layer v2.5
 * -------------------------------------------
 * Order (after middleware probe + Google crawler):
 * 1) Verified Google crawler flag
 * 2) UAE (AE) — always allow (IP/ASN/VPN/hosting/provider ignored)
 * 3) IPinfo failure / unknown country → allow (fail-open)
 * 4) Explicit blocked countries (JO, EG, SY, TR)
 * 5) IP / provider / ASN blacklists (non-AE only)
 * 6) Other allowlisted countries (MA, SA, OM, KW)
 * 7) VPN / proxy / tor / relay / hosting (non-allowlisted)
 * 8) Hosting provider keywords → else country_not_allowed
 */

import { isBlockedIP, isBlockedIPRange } from "./blocklist";
import {
  isProviderBlacklisted,
  isAsnBlacklisted,
  normalizeAsn
} from "./blacklists";
import { decideCountryAccess } from "./access-decision";

/** GTHost ASN — dedicated block reason (IPinfo-verified ASN only). */
const BLOCKED_ASN_GTHOST = "63023";

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
  TURKEY: "TR",
  "UNITED ARAB EMIRATES": "AE",
  UAE: "AE",
  MOROCCO: "MA",
  "SAUDI ARABIA": "SA",
  KSA: "SA",
  OMAN: "OM",
  KUWAIT: "KW"
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
  // RULE: Verified Google crawler (set only after IP/DNS / ASN verification)
  // -------------------------------------------------------------------------
  if (context.isGoogleBot) {
    return {
      decision: "allow",
      allow: true,
      matchedRules: ["allowed_verified_google_crawler"],
      reason: "allowed_verified_google_crawler",
      country,
      blockType: null,
      matchedProvider: null
    };
  }

  // -------------------------------------------------------------------------
  // UAE / unknown / blocked countries (AE always before IP/VPN/hosting)
  // -------------------------------------------------------------------------
  const geoEarly = decideCountryAccess({
    country,
    blockedCountries,
    allowedCountries,
    ipinfoOk: ipResult.ok !== false
  });

  if (geoEarly.reason === "allowed_uae") {
    return {
      decision: "allow",
      allow: true,
      matchedRules: ["allowed_uae"],
      reason: "allowed_uae",
      country: "AE",
      blockType: null,
      matchedProvider: null
    };
  }

  if (geoEarly.reason === "ipinfo_fail_open") {
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

  if (geoEarly.reason === "unknown_country_fail_open") {
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

  if (geoEarly.reason === "blocked_country") {
    return {
      decision: "block",
      allow: false,
      matchedRules: ["blocked_country"],
      reason: "blocked_country",
      country: geoEarly.country,
      blockType: "country",
      matchedProvider: null
    };
  }

  // -------------------------------------------------------------------------
  // Non-AE: IP / provider / ASN blacklists
  // -------------------------------------------------------------------------
  const clientIp =
    (ipResult.ip && String(ipResult.ip)) ||
    (info && info.ip ? String(info.ip) : "") ||
    "";

  const denylist = Array.isArray(rulesConfig.blockedIps)
    ? rulesConfig.blockedIps
    : [];
  const ipDenied =
    isBlockedIP(clientIp) ||
    denylist.some((entry) => String(entry).trim() === clientIp.trim());

  if (clientIp && isBlockedIPRange(clientIp)) {
    return {
      decision: "block",
      allow: false,
      matchedRules: ["blocked_ip_range"],
      reason: "blocked_ip_range",
      country,
      blockType: "ip",
      matchedProvider: null
    };
  }

  if (clientIp && ipDenied) {
    return {
      decision: "block",
      allow: false,
      matchedRules: ["ip_blacklist"],
      reason: "ip_blacklist",
      country,
      blockType: "ip",
      matchedProvider: null
    };
  }

  if (info) {
    const providerHit = isProviderBlacklisted(
      info.privacy_service || info.provider || null,
      info.company || null,
      info.privacy_service || null
    );

    if (providerHit.matched) {
      return {
        decision: "block",
        allow: false,
        matchedRules: ["provider_blacklist"],
        reason: "provider_blacklist",
        country,
        blockType: "provider",
        matchedProvider: providerHit.value
      };
    }

    if (normalizeAsn(info.asn) === BLOCKED_ASN_GTHOST) {
      return {
        decision: "block",
        allow: false,
        matchedRules: ["blocked_asn_gthost"],
        reason: "blocked_asn_gthost",
        country,
        blockType: "asn",
        matchedProvider: "AS63023"
      };
    }

    if (isAsnBlacklisted(info.asn)) {
      return {
        decision: "block",
        allow: false,
        matchedRules: ["asn_blacklist"],
        reason: "asn_blacklist",
        country,
        blockType: "asn",
        matchedProvider: null
      };
    }
  }

  // -------------------------------------------------------------------------
  // Other allowlisted countries (MA, SA, OM, KW) — before VPN/hosting
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

  if (info) {
    // -----------------------------------------------------------------------
    // RULE 4: Strict gate — vpn | proxy | tor | relay | hosting
    // (only for countries outside the allowlist)
    // -----------------------------------------------------------------------
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
      const hostingHit = matchHostingProvider(
        info.asn,
        info.company,
        rulesConfig.hostingProviderKeywords || []
      );

      if (hostingHit.matched) {
        return {
          decision: "block",
          allow: false,
          matchedRules: ["blocked_hosting_provider"],
          reason: "blocked_hosting_provider",
          country,
          blockType: "hosting_provider",
          matchedProvider: hostingHit.keyword
        };
      }
    }
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
