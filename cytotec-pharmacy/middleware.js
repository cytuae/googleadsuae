/**
 * Edge security middleware — Security Layer v2 + Device Fingerprint v1
 * -------------------------------------------------------------------
 * Check order:
 *   0. Bypass fingerprint API + /access-denied (no redirect loops)
 *   1. Probe paths (.env / .git / wp-admin / xmlrpc) → 403
 *   2. Verified Google crawlers (IP ranges / reverse+forward DNS)
 *   3. Blocked IP ranges (e.g. 45.45.237.0/24) → 403 blocked_ip_range
 *   4. IPinfo lookup
 *   5. Verified Google via AS15169 + Google LLC + Googlebot/AdsBot UA
 *      (before blocked_hosting) → allowed_verified_google_crawler
 *   6. Suspicious visitorId / security_blocked cookie:
 *        VISITOR_BLOCK_MODE=monitor + UAE residential → allow + flag
 *        else → 403 blocked_visitor_id
 *   7. Remaining IP / provider / ASN / geo / hosting rules
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
import { resolveSuspiciousVisitorDecision } from "./security/visitor-block";

export const config = {
  matcher: [
    "/",
    "/index.html",
    "/((?!_next(?:/|$)|assets(?:/|$)|favicon\\.ico$|robots\\.txt$|sitemap\\.xml$|feed\\.xml$|.*\\.(?:ico|png|jpe?g|gif|webp|svg|avif|css|js|mjs|map|woff2?|ttf|eot|txt|xml)$).*)"
  ]
};

/**
 * Paths that skip the public security gate (auth handled elsewhere).
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
 * Hard-block common credential / CMS probes.
 * @param {string} pathname
 * @returns {boolean}
 */
function isSecurityProbePath(pathname) {
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

/**
 * @param {import('next/server').NextRequest} request
 * @returns {{ gclid: string|null, gbraid: string|null, wbraid: string|null }}
 */
function readAdsClickIds(request) {
  const q = request.nextUrl.searchParams;
  return {
    gclid: q.get("gclid") || request.cookies.get("gclid")?.value || null,
    gbraid: q.get("gbraid") || request.cookies.get("gbraid")?.value || null,
    wbraid: q.get("wbraid") || request.cookies.get("wbraid")?.value || null
  };
}

/**
 * @param {import('next/server').NextRequest} request
 * @param {{ requestId?: string, reason?: string, engineVersion?: string, clearSecurityBlocked?: boolean }} [meta]
 * @returns {import('next/server').NextResponse}
 */
function serveLanding(request, meta = {}) {
  const url = request.nextUrl.clone();
  /** @type {Record<string, string>} */
  const headers = {
    "x-security-engine": meta.engineVersion || "2.4.0",
    "x-security-decision": "allow"
  };
  if (meta.requestId) headers["x-request-id"] = meta.requestId;
  if (meta.reason) headers["x-security-reason"] = meta.reason;

  /** @type {import('next/server').NextResponse} */
  let res;
  if (url.pathname === "/" || url.pathname === "") {
    url.pathname = "/index.html";
    res = NextResponse.rewrite(url, { headers });
  } else {
    res = NextResponse.next();
    for (const [k, v] of Object.entries(headers)) {
      res.headers.set(k, v);
    }
  }

  if (meta.clearSecurityBlocked) {
    res.cookies.set("security_blocked", "", {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      path: "/",
      maxAge: 0
    });
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
    if (isSecurityBypassPath(request)) {
      return NextResponse.next();
    }

    const securityConfig = getSecurityConfig();
    const clientIp = extractClientIP(request);
    const pathname = request.nextUrl.pathname || "";

    // Probe / credential scans — always hard 403
    if (isSecurityProbePath(pathname) && isEnforcementEnabled(securityConfig)) {
      try {
        await logVisit(
          {
            timestamp: new Date().toISOString(),
            method: request.method,
            path: pathname,
            ip: clientIp,
            requestId,
            rulesResult: {
              decision: "block",
              allow: false,
              matchedRules: ["blocked_probe_path"],
              reason: "blocked_probe_path",
              country: null,
              blockType: "probe",
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
        blockType: "probe",
        country: null,
        reason: "blocked_probe_path"
      });
    }

    // Verified Google crawlers — before Hosting/VPN/Proxy/geo/IP-range blocks.
    const googleVerify = await verifyGoogleCrawlerRequest(request, clientIp);
    if (googleVerify.verified) {
      try {
        await logVisit(
          {
            timestamp: new Date().toISOString(),
            method: request.method,
            path: pathname,
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
            path: pathname,
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

    const ipResult = await checkIP(request, { config: securityConfig });

    // Google AdsBot/Googlebot + AS15169 + Google LLC — before blocked_hosting
    if (isTrustedSecurityBypassBot(request, ipResult)) {
      try {
        await logVisit(
          {
            timestamp: new Date().toISOString(),
            method: request.method,
            path: pathname,
            ip: ipResult.ip || clientIp,
            requestId,
            ipResult,
            rulesResult: {
              decision: "allow",
              allow: true,
              matchedRules: ["allowed_verified_google_crawler"],
              reason: "allowed_verified_google_crawler",
              country: (ipResult.info && ipResult.info.country) || null,
              blockType: null,
              matchedProvider: "AS15169"
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

    // Device Fingerprint — after IPinfo so UAE residential can be monitor-only
    if (securityConfig.providers.fingerprint !== false) {
      const fpGate = evaluateFingerprintCookies(request);
      if (fpGate.suspicious && isEnforcementEnabled(securityConfig)) {
        const adsIds = readAdsClickIds(request);
        const decision = resolveSuspiciousVisitorDecision({
          mode: securityConfig.visitorBlockMode,
          ipInfo: ipResult.info || null,
          visitorId: fpGate.visitorId
        });

        if (decision.monitorOnly) {
          const timestamp = new Date().toISOString();
          try {
            await logVisit(
              {
                timestamp,
                method: request.method,
                path: pathname,
                ip: ipResult.ip || clientIp,
                requestId,
                ipResult,
                flagged: true,
                visitorId: decision.visitorId,
                gclid: adsIds.gclid,
                gbraid: adsIds.gbraid,
                wbraid: adsIds.wbraid,
                rulesResult: {
                  decision: "allow",
                  allow: true,
                  matchedRules: ["monitored_suspicious_visitor"],
                  reason: "monitored_suspicious_visitor",
                  country:
                    (ipResult.info && ipResult.info.country) || "AE",
                  blockType: "fingerprint",
                  matchedProvider: decision.visitorId,
                  flagged: true
                }
              },
              { config: securityConfig }
            );
          } catch {
            // ignore
          }

          console.info(
            JSON.stringify({
              flagged: true,
              reason: "monitored_suspicious_visitor",
              visitorId: decision.visitorId,
              ip: ipResult.ip || clientIp,
              gclid: adsIds.gclid,
              gbraid: adsIds.gbraid,
              timestamp
            })
          );

          return serveLanding(request, {
            requestId,
            reason: "monitored_suspicious_visitor",
            engineVersion: securityConfig.version,
            clearSecurityBlocked: true
          });
        }

        try {
          await logVisit(
            {
              timestamp: new Date().toISOString(),
              method: request.method,
              path: pathname,
              ip: ipResult.ip || clientIp,
              requestId,
              ipResult,
              rulesResult: {
                decision: "block",
                allow: false,
                matchedRules: ["blocked_visitor_id"],
                reason: "blocked_visitor_id",
                country: (ipResult.info && ipResult.info.country) || null,
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
          country: (ipResult.info && ipResult.info.country) || null,
          reason: "blocked_visitor_id"
        });
      }
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
          path: pathname,
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
      engineVersion: "2.4.0"
    });
  }
}
