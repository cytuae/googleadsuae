/**
 * Security configuration — Security Layer v2
 * ------------------------------------------
 * Secrets stay in env (IPINFO_TOKEN on Vercel). Never log or return the token.
 *
 * Permanent blacklists (edit JSON, redeploy — no middleware changes):
 *   - security/ip-blacklist.json
 *   - security/provider-blacklist.json
 *   - security/asn-blacklist.json
 *   - security/fingerprint-blacklist.json  (FingerprintJS visitorId strings)
 */

import { BLOCKED_IPS } from "./blocklist";

/** @typedef {'off' | 'monitor' | 'enforce'} SecurityMode */

/**
 * Datacenter / cloud ASN–company keywords (case-insensitive substring match).
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
  "Cloudflare",
  "Fastly",
  "Akamai",
  "Private Relay",
  "iCloud Private Relay"
];

/**
 * @returns {Object}
 */
export function getSecurityConfig() {
  return {
    mode: "enforce",

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
      // SA = Saudi Arabia — geo allow runs before VPN/hosting gates
      allowedCountries: ["AE", "MA", "SA", "OM", "KW"],
      blockedCountries: ["JO", "EG", "SY", "YE", "SD", "PK"],
      // Sourced from security/ip-blacklist.json — add future IPs there
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

    version: "2.2.0"
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
