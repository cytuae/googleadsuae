/**
 * Admin auth for /admin/security
 * ------------------------------
 * Password from SECURITY_ADMIN_PASSWORD (Vercel env). Never expose it.
 * Session cookie is an HMAC-signed token — no JWT library required.
 */

import { createHmac, timingSafeEqual } from "crypto";

export const ADMIN_COOKIE = "sec_admin_session";
const SESSION_TTL_SEC = 60 * 60 * 12; // 12 hours

/**
 * @returns {string}
 */
export function getAdminPassword() {
  return String(process.env.SECURITY_ADMIN_PASSWORD || "").trim();
}

/**
 * @returns {boolean}
 */
export function isAdminConfigured() {
  return getAdminPassword().length >= 8;
}

/**
 * @param {string} password
 * @returns {boolean}
 */
export function verifyAdminPassword(password) {
  const expected = getAdminPassword();
  if (!expected || typeof password !== "string") return false;
  const a = Buffer.from(password);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  try {
    return timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

/**
 * @param {string} value
 * @returns {string}
 */
function sign(value) {
  const secret = getAdminPassword();
  return createHmac("sha256", secret).update(value).digest("base64url");
}

/**
 * @returns {string}
 */
export function createAdminSessionToken() {
  const exp = Math.floor(Date.now() / 1000) + SESSION_TTL_SEC;
  const payload = `v1.${exp}`;
  return `${payload}.${sign(payload)}`;
}

/**
 * @param {string|undefined|null} token
 * @returns {boolean}
 */
export function verifyAdminSessionToken(token) {
  if (!token || typeof token !== "string") return false;
  if (!isAdminConfigured()) return false;

  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const [ver, expStr, sig] = parts;
  if (ver !== "v1") return false;
  const exp = Number(expStr);
  if (!Number.isFinite(exp) || exp * 1000 < Date.now()) return false;

  const payload = `${ver}.${expStr}`;
  const expected = sign(payload);
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  try {
    return timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

/**
 * @param {import('next/server').NextRequest} request
 * @returns {boolean}
 */
export function isAdminAuthenticated(request) {
  const token = request.cookies.get(ADMIN_COOKIE)?.value;
  return verifyAdminSessionToken(token);
}

export const ADMIN_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: true,
  sameSite: "strict",
  path: "/",
  maxAge: SESSION_TTL_SEC
};
