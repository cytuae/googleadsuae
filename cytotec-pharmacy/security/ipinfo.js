/**
 * IPinfo provider — Privacy Detection + core enrichment
 * ----------------------------------------------------
 * Privacy: https://ipinfo.io/{ip}/privacy
 * Core:    https://ipinfo.io/{ip}/json  (country / ASN / company)
 *
 * Token from process.env.IPINFO_TOKEN only — never logged or returned.
 * Failures return ok:false so middleware can fail-open (never 500).
 */

/**
 * @typedef {Object} IPInfoNormalized
 * @property {string} ip
 * @property {string|null} country
 * @property {string|null} city
 * @property {string|null} region
 * @property {string|null} asn
 * @property {string|null} company
 * @property {boolean|null} is_anonymous
 * @property {boolean|null} is_proxy
 * @property {boolean|null} is_vpn
 * @property {boolean|null} is_relay
 * @property {boolean|null} is_tor
 * @property {boolean|null} is_hosting
 * @property {string|null} [privacy_service]
 */

/**
 * @typedef {Object} IPCheckResult
 * @property {boolean} ok
 * @property {boolean} allow
 * @property {string} ip
 * @property {IPInfoNormalized|null} info
 * @property {Object} meta
 * @property {string} [reason]
 * @property {boolean} [cached]
 */

const IPINFO_BASE = "https://ipinfo.io";

/** @type {Map<string, { expiresAt: number, value: IPInfoNormalized }>} */
const ipCache = new Map();

const DEFAULT_TIMEOUT_MS = 2000;
const DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000;
const MAX_CACHE_ENTRIES = 500;

/**
 * @returns {string}
 */
function getToken() {
  return (process.env.IPINFO_TOKEN || "").trim();
}

/**
 * @param {unknown} value
 * @returns {string|null}
 */
function asNullableString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed.length ? trimmed : null;
}

/**
 * @param {unknown} value
 * @returns {boolean|null}
 */
function asNullableBoolean(value) {
  if (typeof value === "boolean") return value;
  return null;
}

/**
 * Detect real visitor IP from Vercel / proxy headers (left-most public hop).
 * @param {Request} request
 * @returns {string}
 */
export function extractClientIP(request) {
  const candidates = [
    request.headers.get("x-real-ip"),
    request.headers.get("x-vercel-forwarded-for")?.split(",")[0],
    request.headers.get("cf-connecting-ip"),
    request.headers.get("x-forwarded-for")?.split(",")[0]
  ];

  for (let i = 0; i < candidates.length; i++) {
    const raw = (candidates[i] || "").trim();
    if (!raw) continue;
    // Strip IPv4-mapped IPv6 prefix if present
    const ip = raw.replace(/^::ffff:/i, "");
    if (ip && ip !== "unknown") return ip;
  }

  return "unknown";
}

/**
 * @param {string} ip
 * @returns {boolean}
 */
export function isLookupableIP(ip) {
  if (!ip || ip === "unknown") return false;
  if (ip === "::1" || ip === "127.0.0.1") return false;
  if (ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("127.")) {
    return false;
  }
  if (ip.toLowerCase().startsWith("fc") || ip.toLowerCase().startsWith("fd")) {
    return false;
  }
  if (ip.toLowerCase().startsWith("fe80:")) return false;
  const m = /^172\.(\d+)\./.exec(ip);
  if (m) {
    const second = Number(m[1]);
    if (second >= 16 && second <= 31) return false;
  }
  return true;
}

/**
 * Parse classic `org` field: "AS15169 Google LLC"
 * @param {string|null} org
 * @returns {{ asn: string|null, company: string|null }}
 */
function parseOrg(org) {
  if (!org) return { asn: null, company: null };
  const m = /^(AS\d+)\s+(.+)$/i.exec(org.trim());
  if (m) {
    return { asn: m[1].toUpperCase(), company: m[2].trim() };
  }
  return { asn: null, company: org.trim() };
}

/**
 * @param {any} privacy
 * @param {any} core
 * @param {string} fallbackIp
 * @returns {IPInfoNormalized}
 */
export function normalizeIPInfo(privacy, core, fallbackIp) {
  const p = privacy && typeof privacy === "object" ? privacy : {};
  const c = core && typeof core === "object" ? core : {};

  // Support legacy single-payload normalize (tests / old callers)
  if (arguments.length === 2 && typeof core === "string") {
    const raw = privacy && typeof privacy === "object" ? privacy : {};
    const fallback = core;
    const geo = raw.geo && typeof raw.geo === "object" ? raw.geo : {};
    const as = raw.as && typeof raw.as === "object" ? raw.as : {};
    const anonymousObj =
      raw.anonymous && typeof raw.anonymous === "object" ? raw.anonymous : null;
    const privacyObj =
      raw.privacy && typeof raw.privacy === "object" ? raw.privacy : null;
    const orgParsed = parseOrg(asNullableString(raw.org));

    return {
      ip: asNullableString(raw.ip) || fallback,
      country:
        asNullableString(geo.country_code) ||
        asNullableString(raw.country) ||
        null,
      city: asNullableString(geo.city) || asNullableString(raw.city) || null,
      region:
        asNullableString(geo.region) || asNullableString(raw.region) || null,
      asn: asNullableString(as.asn) || orgParsed.asn,
      company:
        asNullableString(as.name) ||
        orgParsed.company ||
        asNullableString(raw.org),
      is_anonymous: asNullableBoolean(raw.is_anonymous),
      is_proxy:
        asNullableBoolean(anonymousObj?.is_proxy) ??
        asNullableBoolean(privacyObj?.proxy) ??
        asNullableBoolean(raw.proxy),
      is_vpn:
        asNullableBoolean(anonymousObj?.is_vpn) ??
        asNullableBoolean(privacyObj?.vpn) ??
        asNullableBoolean(raw.vpn),
      is_relay:
        asNullableBoolean(anonymousObj?.is_relay) ??
        asNullableBoolean(privacyObj?.relay) ??
        asNullableBoolean(raw.relay),
      is_tor:
        asNullableBoolean(anonymousObj?.is_tor) ??
        asNullableBoolean(privacyObj?.tor) ??
        asNullableBoolean(raw.tor),
      is_hosting:
        asNullableBoolean(privacyObj?.hosting) ??
        asNullableBoolean(raw.hosting) ??
        asNullableBoolean(raw.is_hosting),
      privacy_service: asNullableString(privacyObj?.service) || asNullableString(raw.service)
    };
  }

  const orgParsed = parseOrg(asNullableString(c.org));
  const vpn = asNullableBoolean(p.vpn);
  const proxy = asNullableBoolean(p.proxy);
  const tor = asNullableBoolean(p.tor);
  const relay = asNullableBoolean(p.relay);
  const hosting = asNullableBoolean(p.hosting);

  return {
    ip: asNullableString(c.ip) || fallbackIp,
    country: asNullableString(c.country) || null,
    city: asNullableString(c.city) || null,
    region: asNullableString(c.region) || null,
    asn: orgParsed.asn,
    company: orgParsed.company,
    is_anonymous: Boolean(vpn || proxy || tor || relay),
    is_proxy: proxy,
    is_vpn: vpn,
    is_relay: relay,
    is_tor: tor,
    is_hosting: hosting,
    privacy_service: asNullableString(p.service)
  };
}

/**
 * @param {string} ip
 * @returns {IPInfoNormalized|null}
 */
function readCache(ip) {
  const hit = ipCache.get(ip);
  if (!hit) return null;
  if (Date.now() > hit.expiresAt) {
    ipCache.delete(ip);
    return null;
  }
  return hit.value;
}

/**
 * @param {string} ip
 * @param {IPInfoNormalized} value
 * @param {number} ttlMs
 */
function writeCache(ip, value, ttlMs) {
  if (ipCache.size >= MAX_CACHE_ENTRIES) {
    const oldestKey = ipCache.keys().next().value;
    if (oldestKey !== undefined) ipCache.delete(oldestKey);
  }
  ipCache.set(ip, {
    value,
    expiresAt: Date.now() + ttlMs
  });
}

/**
 * @param {string} ip
 * @returns {IPInfoNormalized}
 */
function emptyInfo(ip) {
  return {
    ip,
    country: null,
    city: null,
    region: null,
    asn: null,
    company: null,
    is_anonymous: null,
    is_proxy: null,
    is_vpn: null,
    is_relay: null,
    is_tor: null,
    is_hosting: null,
    privacy_service: null
  };
}

/**
 * @param {string} pathWithIp — e.g. `/1.2.3.4/privacy`
 * @param {string} token
 * @param {AbortSignal} signal
 * @param {typeof fetch} fetchImpl
 */
async function fetchJson(pathWithIp, token, signal, fetchImpl) {
  // Classic IPinfo endpoints expect token as query param (never log this URL).
  const url = `${IPINFO_BASE}${pathWithIp}?token=${encodeURIComponent(token)}`;
  const response = await fetchImpl(url, {
    method: "GET",
    headers: {
      Accept: "application/json"
    },
    signal
  });
  if (!response.ok) {
    return { ok: false, status: response.status, data: null };
  }
  try {
    const data = await response.json();
    return { ok: true, status: response.status, data };
  } catch {
    return { ok: false, status: response.status, data: null };
  }
}

/**
 * Query IPinfo Privacy Detection (+ core enrichment for ASN/company/country).
 *
 * @param {string} ip
 * @param {{
 *   token?: string,
 *   timeoutMs?: number,
 *   cacheTtlMs?: number,
 *   fetchImpl?: typeof fetch
 * }} [options]
 * @returns {Promise<{ info: IPInfoNormalized, cached: boolean, ok: boolean, reason: string }>}
 */
export async function getIPInfo(ip, options = {}) {
  const token = (options.token ?? getToken()).trim();
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const cacheTtlMs = options.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
  const fetchImpl = options.fetchImpl || fetch;

  if (!ip || !isLookupableIP(ip)) {
    return {
      info: emptyInfo(ip || "unknown"),
      cached: false,
      ok: false,
      reason: "ip_not_lookupable"
    };
  }

  if (!token) {
    return {
      info: emptyInfo(ip),
      cached: false,
      ok: false,
      reason: "missing_ipinfo_token"
    };
  }

  const cached = readCache(ip);
  if (cached) {
    return {
      info: cached,
      cached: true,
      ok: true,
      reason: "cache_hit"
    };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const encoded = encodeURIComponent(ip);

  try {
    const [privacyResult, coreResult] = await Promise.all([
      fetchJson(`/${encoded}/privacy`, token, controller.signal, fetchImpl),
      fetchJson(`/${encoded}/json`, token, controller.signal, fetchImpl)
    ]);

    // Privacy Detection is required for enforcement signals
    if (!privacyResult.ok || !privacyResult.data) {
      return {
        info: emptyInfo(ip),
        cached: false,
        ok: false,
        reason: privacyResult.status
          ? `ipinfo_privacy_http_${privacyResult.status}`
          : "ipinfo_privacy_failed"
      };
    }

    const info = normalizeIPInfo(
      privacyResult.data,
      coreResult.ok ? coreResult.data : {},
      ip
    );
    writeCache(ip, info, cacheTtlMs);

    return {
      info,
      cached: false,
      ok: true,
      reason: "ipinfo_privacy_ok"
    };
  } catch (error) {
    const aborted =
      error &&
      typeof error === "object" &&
      "name" in error &&
      error.name === "AbortError";

    return {
      info: emptyInfo(ip),
      cached: false,
      ok: false,
      reason: aborted ? "ipinfo_timeout" : "ipinfo_network_error"
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Middleware-facing IP check. Never throws; never blocks by itself.
 *
 * @param {Request} request
 * @param {{ config?: Object }} [context]
 * @returns {Promise<IPCheckResult>}
 */
export async function checkIP(request, context = {}) {
  const config = context.config || {};
  const ipinfoConfig = config.ipinfo || {};
  const ip = extractClientIP(request);

  if (config.providers && config.providers.ipinfo === false) {
    return {
      ok: true,
      allow: true,
      ip,
      info: emptyInfo(ip),
      meta: { skipped: true },
      reason: "ipinfo_disabled",
      cached: false
    };
  }

  const result = await getIPInfo(ip, {
    timeoutMs: ipinfoConfig.timeoutMs,
    cacheTtlMs: ipinfoConfig.cacheTtlMs
  });

  return {
    ok: result.ok,
    allow: true,
    ip,
    info: result.info,
    meta: {
      provider: "ipinfo",
      endpoint: `${IPINFO_BASE}/{ip}/privacy`
    },
    reason: result.reason,
    cached: result.cached
  };
}
