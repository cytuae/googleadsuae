/**
 * Security configuration — Security Layer v2.5
 * --------------------------------------------
 * Secrets stay in env (IPINFO_TOKEN on Vercel). Never log or return the token.
 *
 * AE (UAE) is always allowed in middleware/rules — never blocked by IP/ASN/
 * provider/VPN/hosting/fingerprint. Fingerprint denylist is monitor-only.
 *
 * Permanent lists (JSON):
 *   - security/ip-blacklist.json
 *   - security/provider-blacklist.json
 *   - security/asn-blacklist.json
 *   - security/fingerprint-blacklist.json  (monitor-only visitorIds)
 */

import { BLOCKED_IPS } from "./blocklist";
import { getVisitorBlockMode } from "./visitor-block";

/** @typedef {'off' | 'monitor' | 'enforce'} SecurityMode */

/**
 * Datacenter / cloud ASN–company keywords (case-insensitive substring match).
 * Do NOT include Etisalat, Du, Cloudflare, or Apple Private Relay — those
 * must never block UAE visitors (AE is short-circuited before this list).
 */
export const HOSTING_PROVIDER_KEYWORDS = [
  "Amazon",
  "AWS",
  "Google Cloud",
  "Microsoft Azure",
  "Oracle",
  "DigitalOcean",
  "Hetzner",
  "OVH",
  "Linode",
  "Vultr",
  "Alibaba",
  "Tencent",
  "Fastly",
  "Akamai"
];

/**
 * @returns {Object}
 */
export function getSecurityConfig() {
  return {
    mode: "enforce",

    /**
     * Legacy env VISITOR_BLOCK_MODE — fingerprints are always monitor-only
     * (never HTTP 403) regardless of this value.
     */
    visitorBlockMode: getVisitorBlockMode(),

    providers: {
      ipinfo: true,
      fingerprint: true,
      rules: true,
      logger: true
    },

    ipinfo: {
      timeoutMs: 2500,
      cacheTtlMs: 5 * 60 * 1000
    },

    rules: {
      // AE always allowed in middleware before other gates.
      // Other GCC allowlist countries skip VPN/hosting false-positives.
      allowedCountries: ["AE", "MA", "SA", "OM", "KW"],
      // Explicit geo blocks
      blockedCountries: ["JO", "EG", "SY", "TR"],
      blockedIps: [...BLOCKED_IPS],
      blockUnknownCountry: false,
      blockVpn: true,
      blockProxy: true,
      blockRelay: true,
      blockTor: true,
      blockHosting: true,
      blockHostingProviders: true,
      hostingProviderKeywords: HOSTING_PROVIDER_KEYWORDS
    },

    version: "2.5.0"
  };
}

/**
 * @param {ReturnType<typeof getSecurityConfig>} [config]
 * @returns {boolean}
 */
export function isEnforcementEnabled(config = getSecurityConfig()) {
  return config.mode === "enforce";
}

/**
 * @returns {boolean}
 */
export function isDevelopment() {
  return process.env.NODE_ENV === "development";
}
