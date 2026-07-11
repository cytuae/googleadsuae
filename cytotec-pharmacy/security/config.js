/**
 * Security configuration — Strict Security Gate v1
 * ------------------------------------------------
 * Secrets stay in env (IPINFO_TOKEN on Vercel). Never log or return the token.
 */

/** @typedef {'off' | 'monitor' | 'enforce'} SecurityMode */

/**
 * Datacenter / cloud ASN–company keywords (case-insensitive substring match).
 */
export const HOSTING_PROVIDER_KEYWORDS = [
  "Amazon",
  "AWS",
  "Google Cloud",
  "Google LLC",
  "Microsoft Azure",
  "Azure",
  "Oracle Cloud",
  "Oracle",
  "DigitalOcean",
  "Hetzner",
  "OVH",
  "Linode",
  "Vultr",
  "Alibaba Cloud",
  "Tencent Cloud",
  "Cloudflare",
  "Fastly",
  "Akamai"
];

/**
 * @returns {{
 *   mode: SecurityMode,
 *   providers: {
 *     ipinfo: boolean,
 *     fingerprint: boolean,
 *     rules: boolean,
 *     logger: boolean
 *   },
 *   ipinfo: {
 *     timeoutMs: number,
 *     cacheTtlMs: number
 *   },
 *   rules: {
 *     allowedCountries: string[],
 *     blockedCountries: string[],
 *     blockUnknownCountry: boolean,
 *     blockVpn: boolean,
 *     blockProxy: boolean,
 *     blockRelay: boolean,
 *     blockTor: boolean,
 *     blockHosting: boolean,
 *     blockHostingProviders: boolean,
 *     hostingProviderKeywords: string[]
 *   },
 *   version: string
 * }}
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
      blockUnknownCountry: false,

      // Strict Security Gate v1
      blockVpn: true,
      blockProxy: true,
      blockRelay: true,
      blockTor: true,
      blockHosting: true,
      blockHostingProviders: true,
      hostingProviderKeywords: HOSTING_PROVIDER_KEYWORDS
    },

    version: "1.5.0-strict-gate-v1"
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
