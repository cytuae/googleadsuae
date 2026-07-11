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
 *   version: string
 * }}
 */
export function getSecurityConfig() {
  return {
    // monitor = run checks & log, never block
    // enforce = allow blocking (future)
    // off = skip providers
    mode: "monitor",

    providers: {
      ipinfo: true,
      fingerprint: false, // scaffold only
      rules: true, // scaffold — currently always allow
      logger: true
    },

    ipinfo: {
      timeoutMs: 2500,
      cacheTtlMs: 5 * 60 * 1000
    },

    version: "1.1.0-ipinfo"
  };
}

/**
 * Whether the security engine should attempt to block requests.
 * Always false until enforcement is intentionally enabled.
 * @param {ReturnType<typeof getSecurityConfig>} [config]
 * @returns {boolean}
 */
export function isEnforcementEnabled(config = getSecurityConfig()) {
  return config.mode === "enforce";
}

/**
 * Development logging helper (Edge-safe).
 * @returns {boolean}
 */
export function isDevelopment() {
  return process.env.NODE_ENV === "development";
}
