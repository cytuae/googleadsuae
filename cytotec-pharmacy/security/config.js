/**
 * Security configuration
 * ----------------------
 * Central place for feature flags, provider toggles, and shared constants.
 * Keep secrets out of this file — use environment variables at runtime.
 *
 * Required env:
 *   IPINFO_TOKEN — IPinfo API bearer token
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
 *     blockedCountries: string[],
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
    // enforce = honor block decisions from applyRules()
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
      // ISO 3166-1 alpha-2
      blockedCountries: ["JO"],
      // Disabled for now — do not evaluate these signals
      blockVpn: false,
      blockProxy: false,
      blockRelay: false,
      blockHosting: false
    },

    version: "1.2.0-country-block"
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
