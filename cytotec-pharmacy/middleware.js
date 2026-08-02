/**
 * Edge security middleware — Security Layer v2 + Device Fingerprint v1
 * -------------------------------------------------------------------
 * Check order:
 *   0. Bypass fingerprint API + /access-denied (no redirect loops)
 *   1. Verified Google crawlers (IP ranges / reverse+forward DNS)
 *   2. Blocked IP ranges (e.g. 45.45.237.0/24) → 403 blocked_ip_range
 *   3. security_blocked cookie / blocked visitorId → 403 blocked_visitor_id
 *   4. IPinfo lookup
 *   5. trusted_bot_bypass only for AS15169 + Google LLC + Googlebot/AdsBot
 *   6. Remaining IP / provider / ASN / geo / hosting rules
 *
 * Verified Google bots receive the same landing HTML as normal users
 * (no cloaking). Spoofed Google UAs do not bypass hosting/JO blocks.
 *
 * Fail-open on errors. Never 500. Never expose secrets.
 *
 * Excludes: /_next/*, assets, images, css, js, fonts, favicon, robots, sitemap
 */

import { NextResponse } from "next/server";
import { getSecurityConfig, isEnforcementEnabled } from "./security/config";
import { checkIP, extractClientIP } from "./security/ipinfo";
import { applyRules } from "./security/rules";
import { logVisit } from "./security/logger";
import { createForbiddenResponse } from "./security/responses";
import {
  isTrustedSecurityBypassBot,
  verifyGoogleCrawlerRequest
} from "./security/bots";
import { evaluateFingerprintCookies } from "./security/fingerprint";
import { isBlockedIPRange } from "./security/blocklist";

export const config = {
  matcher: [
    "/",
    "/index.html",
    "/((?!_next(?:/|$)|assets(?:/|$)|favicon\\.ico$|robots\\.txt$|sitemap\\.xml$|feed\\.xml$|.*\\.(?:ico|png|jpe?g|gif|webp|svg|avif|css|js|mjs|map|woff2?|ttf|eot|txt|xml)$).*)"
  ]
};

/**
 * Paths that skip the public security gate (auth handled elsewhere).
 * Includes private admin dashboard so geo/IP rules never lock out the owner.
 * @param {import('next/server').NextRequest} request
 * @returns {boolean}
 */
function isSecurityBypassPath(request) {
  const path = request.nextUrl.pathname || "";
  return (
    path === "/api/security/fingerprint" ||
    path.startsWith("/api/security/fingerprint/") ||
    path === "/api/security/whatsapp-click" ||
    path.startsWith("/api/security/whatsapp-click/") ||
    path === "/api/security/ads-config" ||
    path.startsWith("/api/security/ads-config/") ||
    path === "/api/security/ingest-event" ||
    path.startsWith("/api/admin/") ||
    path === "/admin" ||
    path.startsWith("/admin/") ||
    path === "/access-denied" ||
    path === "/access-denied.html"
  );
}

/**
 * @param {import('next/server').NextRequest} request
 * @param {{ requestId?: string, reason?: string, engineVersion?: string }} [meta]
 * @returns {import('next/server').NextResponse}
 */
function serveLanding(request, meta = {}) {
  const url = request.nextUrl.clone();
  /** @type {Record<string, string>} */
  const headers = {
    "x-security-engine": meta.engineVersion || "2.1.0",
    "x-security-decision": "allow"
  };
  if (meta.requestId) headers["x-request-id"] = meta.requestId;
  if (meta.reason) headers["x-security-reason"] = meta.reason;

  if (url.pathname === "/" || url.pathname === "") {
    url.pathname = "/index.html";
    return NextResponse.rewrite(url, { headers });
  }
  const res = NextResponse.next();
  for (const [k, v] of Object.entries(headers)) {
    res.headers.set(k, v);
  }
  return res;
}

/**
 * @returns {string}
 */
function createRequestId() {
  try {
    if (typeof crypto !== "undefined" && crypto.randomUUID) {
      return crypto.randomUUID();
    }
  } catch {
    // ignore
  }
  return `req_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
}

/**
 * @param {import('next/server').NextRequest} request
 */
export async function middleware(request) {
  const requestId = createRequestId();

  try {
    // Fingerprint API, ingest, admin, access-denied — no public gate / no loops
    if (isSecurityBypassPath(request)) {
      return NextResponse.next();
    }

    const securityConfig = getSecurityConfig();
    const clientIp = extractClientIP(request);

    // Verified Google crawlers — before Hosting/VPN/Proxy/geo/IP-range blocks.
    // Same page as normal users (rewrite to index.html only; no alternate HTML).
    const googleVerify = await verifyGoogleCrawlerRequest(request, clientIp);
    if (googleVerify.verified) {
      try {
        await logVisit(
          {
            timestamp: new Date().toISOString(),
            method: request.method,
            path: request.nextUrl.pathname,
            ip: clientIp,
            requestId,
            rulesResult: {
              decision: "allow",
              allow: true,
              matchedRules: ["allowed_verified_google_crawler"],
              reason: "allowed_verified_google_crawler",
              country: null,
              blockType: null,
              matchedProvider: googleVerify.bot || null,
              verifyMethod: googleVerify.method
            }
          },
          { config: securityConfig }
        );
      } catch {
        // never fail the request for logging
      }
      return serveLanding(request, {
        requestId,
        reason: "allowed_verified_google_crawler",
        engineVersion: securityConfig.version
      });
    }

    // Blocked IP ranges (e.g. 45.45.237.0/24) — 403 before page HTML
    if (
      isEnforcementEnabled(securityConfig) &&
      clientIp &&
      clientIp !== "unknown" &&
      isBlockedIPRange(clientIp)
    ) {
      try {
        await logVisit(
          {
            timestamp: new Date().toISOString(),
            method: request.method,
            path: request.nextUrl.pathname,
            ip: clientIp,
            requestId,
            rulesResult: {
              decision: "block",
              allow: false,
              matchedRules: ["blocked_ip_range"],
              reason: "blocked_ip_range",
              country: null,
              blockType: "ip",
              matchedProvider: null
            }
          },
          { config: securityConfig }
        );
      } catch {
        // ignore
      }

      return createForbiddenResponse({
        requestId,
        engineVersion: securityConfig.version,
        blockType: "ip",
        country: null,
        reason: "blocked_ip_range"
      });
    }

    if (securityConfig.mode === "off" || !securityConfig.providers.rules) {
      return serveLanding(request, {
        requestId,
        reason: "security_off",
        engineVersion: securityConfig.version
      });
    }

    // Device Fingerprint — cookie / visitorId gate
    if (securityConfig.providers.fingerprint !== false) {
      const fpGate = evaluateFingerprintCookies(request);
      if (fpGate.blocked && isEnforcementEnabled(securityConfig)) {
        try {
          await logVisit(
            {
              timestamp: new Date().toISOString(),
              method: request.method,
              path: request.nextUrl.pathname,
              ip: clientIp,
              requestId,
              rulesResult: {
                decision: "block",
                allow: false,
                matchedRules: ["blocked_visitor_id"],
                reason: "blocked_visitor_id",
                country: null,
                blockType: "fingerprint",
                matchedProvider: fpGate.visitorId
              }
            },
            { config: securityConfig }
          );
        } catch {
          // ignore
        }

        return createForbiddenResponse({
          requestId,
          engineVersion: securityConfig.version,
          blockType: "fingerprint",
          country: null,
          reason: "blocked_visitor_id"
        });
      }
    }

    const ipResult = await checkIP(request, { config: securityConfig });

    // trusted_bot_bypass — AS15169 + Google LLC + Googlebot/AdsBot only
    if (isTrustedSecurityBypassBot(request, ipResult)) {
      try {
        await logVisit(
          {
            timestamp: new Date().toISOString(),
            method: request.method,
            path: request.nextUrl.pathname,
            ip: ipResult.ip || clientIp,
            requestId,
            ipResult,
            rulesResult: {
              decision: "allow",
              allow: true,
              matchedRules: ["trusted_bot_bypass"],
              reason: "trusted_bot_bypass",
              country:
                (ipResult.info && ipResult.info.country) || null,
              blockType: null
            }
          },
          { config: securityConfig }
        );
      } catch {
        // never fail the request for logging
      }
      return serveLanding(request, {
        requestId,
        reason: "trusted_bot_bypass",
        engineVersion: securityConfig.version
      });
    }

    const rulesResult = await applyRules({
      request,
      config: securityConfig,
      ipResult,
      isGoogleBot: false
    });

    try {
      await logVisit(
        {
          timestamp: new Date().toISOString(),
          method: request.method,
          path: request.nextUrl.pathname,
          ip: ipResult.ip,
          ipResult,
          rulesResult,
          requestId
        },
        { config: securityConfig }
      );
    } catch {
      // ignore log errors
    }

    if (
      isEnforcementEnabled(securityConfig) &&
      rulesResult.decision === "block"
    ) {
      return createForbiddenResponse({
        requestId,
        engineVersion: securityConfig.version,
        blockType: rulesResult.blockType || "denied",
        country: rulesResult.country,
        reason: rulesResult.reason
      });
    }

    return serveLanding(request, {
      requestId,
      reason: rulesResult.reason || "allow",
      engineVersion: securityConfig.version
    });
  } catch (error) {
    // Fail-open: never return 500 / MIDDLEWARE_INVOCATION_FAILED
    console.error("[security:error]", {
      requestId,
      message: error && error.message ? error.message : String(error)
    });
    return serveLanding(request, {
      requestId,
      reason: "fail_open",
      engineVersion: "2.1.0"
    });
  }
}
