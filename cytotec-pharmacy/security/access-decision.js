/**
 * Pure access decision helpers (testable without IPinfo / JSON imports).
 */

/**
 * @param {unknown} value
 * @returns {string|null}
 */
export function asCountryCode(value) {
  if (typeof value !== "string") return null;
  const upper = value.trim().toUpperCase();
  if (/^[A-Z]{2}$/.test(upper)) return upper;
  if (upper === "UAE" || upper === "UNITED ARAB EMIRATES") return "AE";
  if (upper === "TURKEY") return "TR";
  if (upper === "JORDAN") return "JO";
  if (upper === "EGYPT") return "EG";
  if (upper === "SYRIA") return "SY";
  return null;
}

/**
 * Core geo gate used by rules/middleware mental model.
 *
 * @param {{
 *   country?: string|null,
 *   blockedCountries?: string[],
 *   allowedCountries?: string[],
 *   ipinfoOk?: boolean
 * }} opts
 * @returns {{ decision: 'allow'|'block', reason: string, country: string|null }}
 */
export function decideCountryAccess(opts = {}) {
  const country = asCountryCode(opts.country);
  const blocked = (opts.blockedCountries || ["JO", "EG", "SY", "TR"]).map((c) =>
    String(c).toUpperCase()
  );
  const allowed = (opts.allowedCountries || ["AE", "MA", "SA", "OM", "KW"]).map(
    (c) => String(c).toUpperCase()
  );

  if (country === "AE") {
    return { decision: "allow", reason: "allowed_uae", country: "AE" };
  }

  if (opts.ipinfoOk === false) {
    return { decision: "allow", reason: "ipinfo_fail_open", country };
  }

  if (!country) {
    return { decision: "allow", reason: "unknown_country_fail_open", country: null };
  }

  if (blocked.includes(country)) {
    return { decision: "block", reason: "blocked_country", country };
  }

  if (allowed.includes(country)) {
    return { decision: "allow", reason: "allowed_country", country };
  }

  return { decision: "block", reason: "country_not_allowed", country };
}

/**
 * Probe paths that must stay hard-blocked.
 * @param {string} pathname
 * @returns {boolean}
 */
export function isSecurityProbePath(pathname) {
  const path = String(pathname || "").toLowerCase();
  if (!path) return false;
  if (path.includes("/.env") || path.endsWith(".env") || /\/\.env(\.|$)/.test(path)) {
    return true;
  }
  if (path.includes("/.git") || path.startsWith("/.git")) return true;
  if (path.includes("wp-admin") || path.includes("wp-login")) return true;
  if (path.includes("xmlrpc.php")) return true;
  return false;
}
