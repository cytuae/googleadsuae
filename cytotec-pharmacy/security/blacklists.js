/**
 * Security Layer v2 — permanent blacklist loader
 * ---------------------------------------------
 * Loads JSON blacklists at build/runtime so you can edit the JSON files
 * without changing middleware or rules logic.
 *
 * Where to add future entries:
 *   - IPs       → security/ip-blacklist.json       → "ips" array
 *   - Providers → security/provider-blacklist.json → "providers" array
 *   - ASNs      → security/asn-blacklist.json      → "asns" array
 *
 * After editing, redeploy. No code changes required.
 */

import ipBlacklistData from "./ip-blacklist.json";
import providerBlacklistData from "./provider-blacklist.json";
import asnBlacklistData from "./asn-blacklist.json";

/**
 * @param {unknown} data
 * @param {string} key
 * @returns {string[]}
 */
function readStringList(data, key) {
  try {
    if (!data || typeof data !== "object") return [];
    const list = /** @type {Record<string, unknown>} */ (data)[key];
    if (!Array.isArray(list)) return [];
    return list
      .map((entry) => String(entry || "").trim())
      .filter(Boolean);
  } catch {
    return [];
  }
}

/**
 * @returns {string[]}
 */
export function loadIpBlacklist() {
  return readStringList(ipBlacklistData, "ips");
}

/**
 * @returns {string[]}
 */
export function loadProviderBlacklist() {
  return readStringList(providerBlacklistData, "providers");
}

/**
 * @returns {string[]}
 */
export function loadAsnBlacklist() {
  return readStringList(asnBlacklistData, "asns");
}

/** @type {ReadonlySet<string>} */
const IP_SET = new Set(loadIpBlacklist());

/** @type {readonly string[]} */
const PROVIDER_LIST = Object.freeze(loadProviderBlacklist());

/** @type {ReadonlySet<string>} */
const ASN_SET = new Set(
  loadAsnBlacklist().map((asn) => normalizeAsn(asn)).filter(Boolean)
);

/**
 * Normalize ASN to digits-only string for comparison (AS13335 → 13335).
 * @param {string|null|undefined} value
 * @returns {string}
 */
export function normalizeAsn(value) {
  if (value == null) return "";
  const raw = String(value).trim().toUpperCase();
  if (!raw) return "";
  const digits = raw.replace(/^AS/, "").replace(/[^0-9]/g, "");
  return digits;
}

/**
 * @param {string|null|undefined} ip
 * @returns {boolean}
 */
export function isIpBlacklisted(ip) {
  if (!ip || typeof ip !== "string") return false;
  return IP_SET.has(ip.trim());
}

/**
 * True if provider or company text contains any blacklist substring.
 * @param {string|null|undefined} provider
 * @param {string|null|undefined} company
 * @param {string|null|undefined} [privacyService]
 * @returns {{ matched: boolean, value: string|null }}
 */
export function isProviderBlacklisted(provider, company, privacyService) {
  const haystack = `${provider || ""} ${company || ""} ${privacyService || ""}`
    .toLowerCase()
    .trim();

  if (!haystack) {
    return { matched: false, value: null };
  }

  for (let i = 0; i < PROVIDER_LIST.length; i++) {
    const entry = PROVIDER_LIST[i];
    if (!entry) continue;
    if (haystack.includes(entry.toLowerCase())) {
      return { matched: true, value: entry };
    }
  }

  return { matched: false, value: null };
}

/**
 * @param {string|null|undefined} asn
 * @returns {boolean}
 */
export function isAsnBlacklisted(asn) {
  const normalized = normalizeAsn(asn);
  if (!normalized) return false;
  return ASN_SET.has(normalized);
}
