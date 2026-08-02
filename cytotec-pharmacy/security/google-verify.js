/**
 * Verified Google crawler detection (Edge-safe)
 * ---------------------------------------------
 * UA alone is never enough. Confirm the client IP via:
 *  1) Official common-crawlers + special-crawlers CIDR lists, or
 *  2) Reverse DNS → hostname mask → forward DNS match
 *
 * Allowed User-Agents (candidates only):
 *  AdsBot-Google | AdsBot-Google-Mobile | Googlebot | Google-Safety
 */

const ALLOWED_GOOGLE_UA =
  /(?:AdsBot-Google-Mobile|AdsBot-Google|Googlebot|Google-Safety)/i;

const COMMON_RANGES_URL =
  "https://developers.google.com/static/crawling/ipranges/common-crawlers.json";
const SPECIAL_RANGES_URL =
  "https://developers.google.com/static/crawling/ipranges/special-crawlers.json";

/** @type {{ fetchedAt: number, prefixes: string[] } | null} */
let rangesCache = null;
const RANGES_TTL_MS = 6 * 60 * 60 * 1000;
const FETCH_TIMEOUT_MS = 2500;

/**
 * @param {Request} request
 * @returns {boolean}
 */
export function isAllowedGoogleCrawlerUserAgent(request) {
  const ua = request.headers.get("user-agent") || "";
  if (!ua) return false;
  return ALLOWED_GOOGLE_UA.test(ua);
}

/**
 * @param {string|null|undefined} ip
 * @returns {boolean}
 */
function isPublicIp(ip) {
  if (!ip || typeof ip !== "string") return false;
  const v = ip.trim().toLowerCase();
  if (!v || v === "unknown") return false;
  if (v.includes(":")) {
    if (v === "::1") return false;
    if (v.startsWith("fc") || v.startsWith("fd") || v.startsWith("fe80")) {
      return false;
    }
    return true;
  }
  if (
    v.startsWith("10.") ||
    v.startsWith("127.") ||
    v.startsWith("192.168.") ||
    v.startsWith("169.254.")
  ) {
    return false;
  }
  const m = /^172\.(\d+)\./.exec(v);
  if (m) {
    const n = Number(m[1]);
    if (n >= 16 && n <= 31) return false;
  }
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(v);
}

/**
 * @param {string} ip
 * @returns {bigint|null}
 */
function ipv4ToBigInt(ip) {
  const parts = ip.split(".").map((p) => Number(p));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return null;
  }
  return (
    (BigInt(parts[0]) << 24n) |
    (BigInt(parts[1]) << 16n) |
    (BigInt(parts[2]) << 8n) |
    BigInt(parts[3])
  );
}

/**
 * @param {string} ip
 * @returns {bigint|null}
 */
function ipv6ToBigInt(ip) {
  // Expand :: and split into 8 hextets
  let v = ip.toLowerCase().split("%")[0];
  if (v.startsWith("[") && v.endsWith("]")) v = v.slice(1, -1);
  if (v.includes(".")) {
    // IPv4-mapped — not needed for Google crawlers typically
    return null;
  }
  const halves = v.split("::");
  if (halves.length > 2) return null;
  let head = halves[0] ? halves[0].split(":") : [];
  let tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  if (halves.length === 1) {
    if (head.length !== 8) return null;
  } else {
    const missing = 8 - head.length - tail.length;
    if (missing < 0) return null;
    head = head.concat(Array(missing).fill("0"), tail);
  }
  if (head.length !== 8) return null;
  let out = 0n;
  for (const h of head) {
    if (!/^[0-9a-f]{1,4}$/.test(h)) return null;
    out = (out << 16n) | BigInt(parseInt(h, 16));
  }
  return out;
}

/**
 * @param {string} ip
 * @param {string} cidr
 * @returns {boolean}
 */
export function ipMatchesCidr(ip, cidr) {
  if (!ip || !cidr) return false;
  const [network, bitsRaw] = String(cidr).split("/");
  const bits = Number(bitsRaw);
  if (!network || !Number.isInteger(bits) || bits < 0) return false;

  if (ip.includes(":") || network.includes(":")) {
    const ipInt = ipv6ToBigInt(ip);
    const netInt = ipv6ToBigInt(network);
    if (ipInt === null || netInt === null || bits > 128) return false;
    if (bits === 0) return true;
    const shift = 128n - BigInt(bits);
    const mask = bits === 128 ? (1n << 128n) - 1n : ((1n << BigInt(bits)) - 1n) << shift;
    return (ipInt & mask) === (netInt & mask);
  }

  const ipInt = ipv4ToBigInt(ip);
  const netInt = ipv4ToBigInt(network);
  if (ipInt === null || netInt === null || bits > 32) return false;
  if (bits === 0) return true;
  const shift = 32n - BigInt(bits);
  const mask = bits === 32 ? 0xffffffffn : ((1n << BigInt(bits)) - 1n) << shift;
  return (ipInt & mask) === (netInt & mask);
}

/**
 * @param {unknown} data
 * @returns {string[]}
 */
function extractPrefixes(data) {
  if (!data || typeof data !== "object") return [];
  const list = /** @type {{ prefixes?: Array<Record<string, string>> }} */ (data)
    .prefixes;
  if (!Array.isArray(list)) return [];
  /** @type {string[]} */
  const out = [];
  for (const row of list) {
    if (!row || typeof row !== "object") continue;
    if (typeof row.ipv4Prefix === "string") out.push(row.ipv4Prefix);
    if (typeof row.ipv6Prefix === "string") out.push(row.ipv6Prefix);
  }
  return out;
}

/**
 * @param {string} url
 * @returns {Promise<string[]>}
 */
async function fetchPrefixFile(url) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: "GET",
      headers: { accept: "application/json" },
      signal: ctrl.signal,
      cache: "no-store"
    });
    if (!res.ok) return [];
    const json = await res.json();
    return extractPrefixes(json);
  } catch {
    return [];
  } finally {
    clearTimeout(timer);
  }
}

/**
 * @returns {Promise<string[]>}
 */
async function getGoogleCrawlerPrefixes() {
  const now = Date.now();
  if (rangesCache && now - rangesCache.fetchedAt < RANGES_TTL_MS) {
    return rangesCache.prefixes;
  }

  const [common, special] = await Promise.all([
    fetchPrefixFile(COMMON_RANGES_URL),
    fetchPrefixFile(SPECIAL_RANGES_URL)
  ]);
  const prefixes = [...common, ...special];
  if (prefixes.length > 0) {
    rangesCache = { fetchedAt: now, prefixes };
  }
  return prefixes;
}

/**
 * @param {string} ip
 * @param {string[]} prefixes
 * @returns {boolean}
 */
export function ipInGoogleCrawlerRanges(ip, prefixes) {
  if (!ip || !Array.isArray(prefixes) || prefixes.length === 0) return false;
  for (let i = 0; i < prefixes.length; i++) {
    if (ipMatchesCidr(ip, prefixes[i])) return true;
  }
  return false;
}

/**
 * @param {string} ip
 * @returns {string|null}
 */
function reverseDnsName(ip) {
  if (ip.includes(":")) {
    const int = ipv6ToBigInt(ip);
    if (int === null) return null;
    let hex = int.toString(16).padStart(32, "0");
    const nibbles = hex.split("").reverse().join(".");
    return `${nibbles}.ip6.arpa`;
  }
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  return `${parts[3]}.${parts[2]}.${parts[1]}.${parts[0]}.in-addr.arpa`;
}

/**
 * @param {string} name
 * @param {"PTR"|"A"|"AAAA"} type
 * @returns {Promise<string[]>}
 */
async function dohQuery(name, type) {
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(
    name
  )}&type=${type}`;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      headers: { accept: "application/dns-json" },
      signal: ctrl.signal,
      cache: "no-store"
    });
    if (!res.ok) return [];
    const json = await res.json();
    const answers = Array.isArray(json.Answer) ? json.Answer : [];
    /** @type {string[]} */
    const out = [];
    for (const a of answers) {
      if (!a || typeof a.data !== "string") continue;
      // PTR data may be "host." with trailing dot
      out.push(String(a.data).replace(/\.$/, "").toLowerCase());
    }
    return out;
  } catch {
    return [];
  } finally {
    clearTimeout(timer);
  }
}

/**
 * @param {string} host
 * @returns {boolean}
 */
function isGoogleCrawlerHostname(host) {
  if (!host) return false;
  const h = host.toLowerCase().replace(/\.$/, "");
  return (
    h.endsWith(".googlebot.com") ||
    h.endsWith(".google.com") ||
    h === "googlebot.com" ||
    h === "google.com"
  );
}

/**
 * Reverse DNS + forward DNS confirmation (Google's documented method).
 * @param {string} ip
 * @returns {Promise<boolean>}
 */
export async function verifyGoogleCrawlerByDns(ip) {
  if (!isPublicIp(ip)) return false;
  const ptrName = reverseDnsName(ip);
  if (!ptrName) return false;

  const ptrs = await dohQuery(ptrName, "PTR");
  const host = ptrs.find((h) => isGoogleCrawlerHostname(h));
  if (!host) return false;

  const isV6 = ip.includes(":");
  const forwards = await dohQuery(host, isV6 ? "AAAA" : "A");
  const normalizedIp = ip.toLowerCase();
  return forwards.some((addr) => addr.toLowerCase() === normalizedIp);
}

/**
 * Full verification: candidate UA + (CIDR ranges OR reverse/forward DNS).
 * Spoofed UA without Google IP → false (no bypass).
 *
 * @param {Request} request
 * @param {string|null|undefined} ip
 * @returns {Promise<{ verified: boolean, method: string|null, bot: string|null }>}
 */
export async function verifyGoogleCrawlerRequest(request, ip) {
  if (!isAllowedGoogleCrawlerUserAgent(request)) {
    return { verified: false, method: null, bot: null };
  }

  const ua = request.headers.get("user-agent") || "";
  let bot = "Googlebot";
  if (/AdsBot-Google-Mobile/i.test(ua)) bot = "AdsBot-Google-Mobile";
  else if (/AdsBot-Google/i.test(ua)) bot = "AdsBot-Google";
  else if (/Google-Safety/i.test(ua)) bot = "Google-Safety";
  else if (/Googlebot/i.test(ua)) bot = "Googlebot";

  if (!isPublicIp(ip)) {
    return { verified: false, method: null, bot };
  }

  try {
    const prefixes = await getGoogleCrawlerPrefixes();
    if (ipInGoogleCrawlerRanges(ip, prefixes)) {
      return { verified: true, method: "google_ip_ranges", bot };
    }
  } catch {
    // fall through to DNS
  }

  try {
    if (await verifyGoogleCrawlerByDns(ip)) {
      return { verified: true, method: "reverse_forward_dns", bot };
    }
  } catch {
    // fail closed for bypass
  }

  return { verified: false, method: null, bot };
}
