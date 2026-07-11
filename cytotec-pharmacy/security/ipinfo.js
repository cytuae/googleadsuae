/**
 * IPinfo provider
 * ---------------
 * Looks up visitor IP intelligence via IPinfo Core/Plus lookup API.
 * Never throws into the request path in a way that blocks the visitor.
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
 * @property {boolean|null} is_hosting
 */

/**
 * @typedef {Object} IPCheckResult
 * @property {boolean} ok
 * @property {boolean} allow - Always true (no blocking in this phase)
 * @property {string} ip
 * @property {IPInfoNormalized|null} info
 * @property {Object} meta
 * @property {string} [reason]
 * @property {boolean} [cached]
 */

const IPINFO_LOOKUP_BASE = "https://api.ipinfo.io/lookup";

/** @type {Map<string, { expiresAt: number, value: IPInfoNormalized }>} */
const ipCache = new Map();

const DEFAULT_TIMEOUT_MS = 2500;
const DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
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
 * Extract client IP from common proxy / platform headers.
 * @param {Request} request
 * @returns {string}
 */
export function extractClientIP(request) {
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) {
    const first = forwarded.split(",")[0]?.trim();
    if (first) return first;
  }

  return (
    request.headers.get("x-real-ip")?.trim() ||
    request.headers.get("cf-connecting-ip")?.trim() ||
    request.headers.get("x-vercel-forwarded-for")?.split(",")[0]?.trim() ||
    "unknown"
  );
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
  // Link-local / unique-local IPv6
  if (ip.toLowerCase().startsWith("fc") || ip.toLowerCase().startsWith("fd")) {
    return false;
  }
  if (ip.toLowerCase().startsWith("fe80:")) return false;
  // IPv4 private 172.16.0.0 – 172.31.255.255
  const m = /^172\.(\d+)\./.exec(ip);
  if (m) {
    const second = Number(m[1]);
    if (second >= 16 && second <= 31) return false;
  }
  return true;
}

/**
 * Normalize heterogeneous IPinfo payloads into a stable shape.
 * Supports nested Core/Plus objects and flatter legacy-style fields.
 *
 * @param {any} raw
 * @param {string} fallbackIp
 * @returns {IPInfoNormalized}
 */
export function normalizeIPInfo(raw, fallbackIp) {
  const data = raw && typeof raw === "object" ? raw : {};
  const geo = data.geo && typeof data.geo === "object" ? data.geo : {};
  const as = data.as && typeof data.as === "object" ? data.as : {};
  const companyObj =
    data.company && typeof data.company === "object" ? data.company : null;
  const anonymousObj =
    data.anonymous && typeof data.anonymous === "object" ? data.anonymous : null;

  const asn =
    asNullableString(as.asn) ||
    asNullableString(data.asn) ||
    asNullableString(data.as) ||
    null;

  const company =
    asNullableString(companyObj?.name) ||
    asNullableString(as.name) ||
    asNullableString(data.as_name) ||
    asNullableString(data.org) ||
    asNullableString(data.company) ||
    null;

  let isAnonymous = asNullableBoolean(data.is_anonymous);
  if (isAnonymous === null && anonymousObj) {
    isAnonymous = Boolean(
      anonymousObj.is_proxy ||
        anonymousObj.is_relay ||
        anonymousObj.is_tor ||
        anonymousObj.is_vpn ||
        anonymousObj.is_anonymous
    );
  }

  let isHosting = asNullableBoolean(data.is_hosting);
  if (isHosting === null && asNullableString(as.type)) {
    isHosting = as.type.toLowerCase() === "hosting";
  }

  return {
    ip: asNullableString(data.ip) || fallbackIp,
    country:
      asNullableString(geo.country_code) ||
      asNullableString(geo.country) ||
      asNullableString(data.country_code) ||
      asNullableString(data.country) ||
      null,
    city: asNullableString(geo.city) || asNullableString(data.city) || null,
    region:
      asNullableString(geo.region) || asNullableString(data.region) || null,
    asn,
    company,
    is_anonymous: isAnonymous,
    is_hosting: isHosting
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
    // Drop oldest insertion (Map preserves insertion order)
    const oldestKey = ipCache.keys().next().value;
    if (oldestKey !== undefined) ipCache.delete(oldestKey);
  }
  ipCache.set(ip, {
    value,
    expiresAt: Date.now() + ttlMs
  });
}

/**
 * Empty-but-valid payload used when lookup is skipped or fails.
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
    is_hosting: null
  };
}

/**
 * Reusable IPinfo lookup with timeout, error handling, and short TTL cache.
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

  try {
    const response = await fetchImpl(`${IPINFO_LOOKUP_BASE}/${encodeURIComponent(ip)}`, {
      method: "GET",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${token}`
      },
      signal: controller.signal
    });

    if (!response.ok) {
      return {
        info: emptyInfo(ip),
        cached: false,
        ok: false,
        reason: `ipinfo_http_${response.status}`
      };
    }

    let raw;
    try {
      raw = await response.json();
    } catch {
      return {
        info: emptyInfo(ip),
        cached: false,
        ok: false,
        reason: "ipinfo_invalid_json"
      };
    }

    const info = normalizeIPInfo(raw, ip);
    writeCache(ip, info, cacheTtlMs);

    return {
      info,
      cached: false,
      ok: true,
      reason: "ipinfo_ok"
    };
  } catch (error) {
    const aborted =
      error &&
      typeof error === "object" &&
      ("name" in error) &&
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
 * Middleware-facing IP check. Always allows the request.
 *
 * @param {Request} request
 * @param {{ config?: Object }} [context]
 * @returns {Promise<IPCheckResult>}
 */
export async function checkIP(request, context = {}) {
  const config = context.config || {};
  const ipinfoConfig = config.ipinfo || {};
  const ip = extractClientIP(request);

  // Provider can be disabled via config without removing it from the pipeline.
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
    allow: true, // never block in this phase
    ip,
    info: result.info,
    meta: {
      provider: "ipinfo",
      endpoint: IPINFO_LOOKUP_BASE
    },
    reason: result.reason,
    cached: result.cached
  };
}
