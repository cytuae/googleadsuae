/**
 * Security configuration — strict IP protection for dr-ohood.clinic
 * -----------------------------------------------------------------
 * Secrets stay in env (IPINFO_TOKEN on Vercel). Never log or return the token.
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
      fingerprint: false,
      rules: true,
      logger: true
    },

    ipinfo: {
      timeoutMs: 2500,
      cacheTtlMs: 5 * 60 * 1000
    },

    rules: {
      allowedCountries: ["AE", "MA"],
      blockedCountries: ["JO", "EG", "SY", "YE", "SD", "PK"],
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

    version: "1.7.0-privacy-api"
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
