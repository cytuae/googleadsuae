/**
 * Edge security middleware — Security Layer v2.5
 * -------------------------------------------------------------------
 * Check order:
 *   0. Bypass security APIs + /access-denied
 *   1. Probe paths (.env / .git / wp-admin / xmlrpc) → 403
 *   2. Verified Google crawlers (IP ranges / reverse+forward DNS)
 *   3. IPinfo lookup (extract country)
 *   4. Google crawler UA + AS15169 / Google LLC → allow
 *   5. country === AE → allow immediately (page + WhatsApp)
 *   6. Fingerprint denylist → monitor-only (never 403)
 *   7. Remaining geo / hosting / VPN rules (non-AE)
 *
 * Fail-open on errors. Never 500. Never expose secrets.
 */

import { NextResponse } from "next/server";
import { getSecurityConfig, isEnforcementEnabled } from "./security/config";
import { checkIP, extractClientIP } from "./security/ipinfo";
import { applyRules, normalizeCountryCode } from "./security/rules";
import { logVisit } from "./security/logger";
import { createForbiddenResponse } from "./security/responses";
import {
  isTrustedSecurityBypassBot,
  verifyGoogleCrawlerRequest
} from "./security/bots";
import { evaluateFingerprintCookies } from "./security/fingerprint";
import { resolveSuspiciousVisitorDecision } from "./security/visitor-block";

export const config = {
  matcher: [
    "/",
    "/index.html",
    "/((?!_next(?:/|$)|assets(?:/|$)|favicon\\.ico$|robots\\.txt$|sitemap\\.xml$|feed\\.xml$|.*\\.(?:ico|png|jpe?g|gif|webp|svg|avif|css|js|mjs|map|woff2?|ttf|eot|txt|xml)$).*)"
  ]
};

/**
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
 * Hard-block common credential / CMS probes only.
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
    "x-security-engine": meta.engineVersion || "2.5.0",
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

  // Always clear legacy hard-block fingerprint cookie
  res.cookies.set("security_blocked", "", {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: 0
  });

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

    // 1) Probe / credential scans — always hard 403
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

    // 2) Verified Google crawlers (IP ranges / DNS) — before hosting/geo
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

    if (securityConfig.mode === "off" || !securityConfig.providers.rules) {
      return serveLanding(request, {
        requestId,
        reason: "security_off",
        engineVersion: securityConfig.version
      });
    }

    // 3) Extract country via IPinfo
    const ipResult = await checkIP(request, { config: securityConfig });
    const country = normalizeCountryCode(
      ipResult.info && ipResult.info.country
    );

    // 4) Google crawler UA + AS15169 / Google LLC — before hosting/geo
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
              country,
              blockType: null,
              matchedProvider: "AS15169"
            }
          },
          { config: securityConfig }
        );
      } catch {
        // ignore
      }
      return serveLanding(request, {
        requestId,
        reason: "allowed_verified_google_crawler",
        engineVersion: securityConfig.version
      });
    }

    // 5) UAE always allowed — page + WhatsApp (ignore IP/ASN/VPN/hosting/fp)
    if (country === "AE") {
      const fpGate = evaluateFingerprintCookies(request);
      const adsIds = readAdsClickIds(request);
      let reason = "allowed_uae";

      if (fpGate.suspicious) {
        const decision = resolveSuspiciousVisitorDecision({
          visitorId: fpGate.visitorId,
          ipInfo: ipResult.info || null
        });
        reason = decision.reason;
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
                matchedRules: ["allowed_uae", "monitored_suspicious_visitor"],
                reason: "monitored_suspicious_visitor",
                country: "AE",
                blockType: null,
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
      } else {
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
                matchedRules: ["allowed_uae"],
                reason: "allowed_uae",
                country: "AE",
                blockType: null
              }
            },
            { config: securityConfig }
          );
        } catch {
          // ignore
        }
      }

      return serveLanding(request, {
        requestId,
        reason,
        engineVersion: securityConfig.version,
        clearSecurityBlocked: true
      });
    }

    // 6) Fingerprint denylist — monitor-only worldwide (never 403)
    if (securityConfig.providers.fingerprint !== false) {
      const fpGate = evaluateFingerprintCookies(request);
      if (fpGate.suspicious) {
        const adsIds = readAdsClickIds(request);
        const decision = resolveSuspiciousVisitorDecision({
          visitorId: fpGate.visitorId,
          ipInfo: ipResult.info || null
        });
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
                country,
                blockType: null,
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
        // Continue to geo/hosting rules — fingerprint alone never blocks
      }
    }

    // 7) Remaining rules (blocked countries, hosting, VPN, …)
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
    console.error("[security:error]", {
      requestId,
      message: error && error.message ? error.message : String(error)
    });
    return serveLanding(request, {
      requestId,
      reason: "fail_open",
      engineVersion: "2.5.0"
    });
  }
}
