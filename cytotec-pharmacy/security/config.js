/**
 * Security configuration
 * ----------------------
 * Phase 1: country allow/block + Google bot bypass.
 * Secrets stay in env (IPINFO_TOKEN on Vercel).
 */

/** @typedef {'off' | 'monitor' | 'enforce'} SecurityMode */

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
 *     blockHosting: boolean
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
      // Audience: UAE + Morocco
      allowedCountries: ["AE", "MA"],
      // Click-fraud sources (phase 1)
      blockedCountries: ["JO", "EG", "SY", "YE", "SD", "PK"],
      // If IPinfo has no country → allow (fail-open)
      blockUnknownCountry: false,
      // Strict: block known proxies even from AE/MA
      blockProxy: true,
      // Still off — enable later if needed
      blockVpn: false,
      blockRelay: false,
      blockHosting: false
    },

    version: "1.4.0-block-proxy"
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
