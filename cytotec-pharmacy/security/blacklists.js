/**
 * Security Layer v2 — permanent blacklist loader
 * ---------------------------------------------
 * Loads JSON blacklists at build/runtime so you can edit the JSON files
 * without changing middleware or rules logic.
 *
 * Where to add future entries:
 *   - IPs           → security/ip-blacklist.json           → "ips" array
 *   - IP ranges     → security/ip-blacklist.json           → "ranges" / "prefixes"
 *   - Providers     → security/provider-blacklist.json     → "providers" array
 *   - ASNs          → security/asn-blacklist.json          → "asns" array
 *   - Fingerprints  → security/fingerprint-blacklist.json  → JSON array of visitorId strings
 *
 * After editing, redeploy. No code changes required.
 */

import ipBlacklistData from "./ip-blacklist.json";
import providerBlacklistData from "./provider-blacklist.json";
import asnBlacklistData from "./asn-blacklist.json";
import fingerprintBlacklistData from "./fingerprint-blacklist.json";

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
export function loadIpRanges() {
  return readStringList(ipBlacklistData, "ranges");
}

/**
 * @returns {string[]}
 */
export function loadIpPrefixes() {
  return readStringList(ipBlacklistData, "prefixes");
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

/**
 * Fingerprint blacklist is a raw JSON array of FingerprintJS visitorId strings.
 * Add future visitorIds directly to security/fingerprint-blacklist.json.
 * @returns {string[]}
 */
export function loadFingerprintBlacklist() {
  try {
    if (Array.isArray(fingerprintBlacklistData)) {
      return fingerprintBlacklistData
        .map((entry) => String(entry || "").trim())
        .filter(Boolean);
    }
    return readStringList(fingerprintBlacklistData, "visitorIds");
  } catch {
    return [];
  }
}

/** @type {ReadonlySet<string>} */
const IP_SET = new Set(loadIpBlacklist());

/** @type {readonly string[]} */
const IP_RANGES = Object.freeze(loadIpRanges());

/** @type {readonly string[]} */
const IP_PREFIXES = Object.freeze(loadIpPrefixes());

/** @type {readonly string[]} */
const PROVIDER_LIST = Object.freeze(loadProviderBlacklist());

/** @type {ReadonlySet<string>} */
const ASN_SET = new Set(
  loadAsnBlacklist().map((asn) => normalizeAsn(asn)).filter(Boolean)
);

/** @type {ReadonlySet<string>} */
const FINGERPRINT_SET = new Set(loadFingerprintBlacklist());

/** Explicit blocked FingerprintJS visitorIds (same source as fingerprint-blacklist.json). */
export const BLOCKED_VISITOR_IDS = Object.freeze([...FINGERPRINT_SET]);

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
 * @param {string} ip
 * @returns {number|null}
 */
function ipv4ToInt(ip) {
  const parts = ip.split(".").map((p) => Number(p));
  if (
    parts.length !== 4 ||
    parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)
  ) {
    return null;
  }
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

/**
 * @param {string} ip
 * @param {string} cidr
 * @returns {boolean}
 */
function ipv4InCidr(ip, cidr) {
  const [network, bitsRaw] = String(cidr).split("/");
  const bits = Number(bitsRaw);
  if (!network || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const ipInt = ipv4ToInt(ip);
  const netInt = ipv4ToInt(network);
  if (ipInt === null || netInt === null) return false;
  if (bits === 0) return true;
  const mask = bits === 32 ? 0xffffffff : (~0 << (32 - bits)) >>> 0;
  return (ipInt & mask) === (netInt & mask);
}

/**
 * Exact IP denylist match (ips array).
 * @param {string|null|undefined} ip
 * @returns {boolean}
 */
export function isIpBlacklisted(ip) {
  if (!ip || typeof ip !== "string") return false;
  return IP_SET.has(ip.trim());
}

/**
 * CIDR / prefix denylist (e.g. 45.45.237.0/24 and 45.45.237.*).
 * @param {string|null|undefined} ip
 * @returns {boolean}
 */
export function isIpRangeBlacklisted(ip) {
  if (!ip || typeof ip !== "string") return false;
  const v = ip.trim();
  if (!v || v === "unknown") return false;

  for (let i = 0; i < IP_PREFIXES.length; i++) {
    const prefix = IP_PREFIXES[i];
    if (prefix && v.startsWith(prefix)) return true;
  }

  if (!v.includes(":")) {
    for (let i = 0; i < IP_RANGES.length; i++) {
      const cidr = IP_RANGES[i];
      if (cidr && ipv4InCidr(v, cidr)) return true;
    }
  }

  return false;
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

/**
 * Exact match against FingerprintJS visitorId blacklist.
 * @param {string|null|undefined} visitorId
 * @returns {boolean}
 */
export function isFingerprintBlacklisted(visitorId) {
  if (!visitorId || typeof visitorId !== "string") return false;
  return FINGERPRINT_SET.has(visitorId.trim());
}
