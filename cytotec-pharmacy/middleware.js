/**
 * Edge security middleware — Security Layer v2 + Device Fingerprint v1
 * -------------------------------------------------------------------
 * Check order:
 *   0. Bypass fingerprint API + /access-denied (no redirect loops)
 *   1. security_blocked cookie / device_fingerprint blacklist → 403
 *   2. IP blacklist → 403
 *   3. Provider/company blacklist → 403
 *   4. ASN blacklist → 403
 *   5. vpn | proxy | tor | relay | hosting
 *
 * Blacklists (edit JSON, redeploy — no middleware logic changes):
 *   security/ip-blacklist.json
 *   security/provider-blacklist.json
 *   security/asn-blacklist.json
 *   security/fingerprint-blacklist.json
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
import { isTrustedSecurityBypassBot } from "./security/bots";
import { evaluateFingerprintCookies } from "./security/fingerprint";
import {
  extractAttribution,
  hasAdClickId,
  primaryClickId
} from "./security/attribution";
import { sendCircuitSignal } from "./security/circuit-signal";

export const config = {
  matcher: [
    "/",
    "/index.html",
    "/((?!_next(?:/|$)|assets(?:/|$)|favicon\\.ico$|robots\\.txt$|sitemap\\.xml$|.*\\.(?:ico|png|jpe?g|gif|webp|svg|avif|css|js|mjs|map|woff2?|ttf|eot|txt)$).*)"
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
    path === "/api/security/ingest-event" ||
    path === "/api/security/circuit" ||
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
 * Run monitoring after the response without holding the 403 open. Falls back
 * to a detached promise outside runtimes that expose NextFetchEvent.waitUntil.
 * @param {import('next/server').NextFetchEvent|undefined} event
 * @param {Promise<void>} promise
 */
function keepAlive(event, promise) {
  try {
    if (event && typeof event.waitUntil === "function") {
      event.waitUntil(promise);
      return;
    }
  } catch {
    // fall through
  }
  void promise.catch(() => {});
}

/**
 * @param {import('next/server').NextRequest} request
 * @param {import('next/server').NextFetchEvent} event
 */
export async function middleware(request, event) {
  const requestId = createRequestId();
  const attribution = extractAttribution(request);

  try {
    // Fingerprint API, ingest, admin, access-denied — no public gate / no loops
    if (isSecurityBypassPath(request)) {
      return NextResponse.next();
    }

    // Google Ads / Statcounter verifiers — never block
    if (isTrustedSecurityBypassBot(request)) {
      try {
        await logVisit(
          {
            timestamp: new Date().toISOString(),
            method: request.method,
            path: request.nextUrl.pathname,
            ip: extractClientIP(request),
            requestId,
            attribution,
            rulesResult: {
              decision: "allow",
              allow: true,
              matchedRules: ["trusted_bot_bypass"],
              reason: "trusted_bot_bypass",
              country: null,
              blockType: null
            }
          },
          {}
        );
      } catch {
        // never fail the request for logging
      }
      return serveLanding(request, {
        requestId,
        reason: "trusted_bot_bypass",
        engineVersion: getSecurityConfig().version
      });
    }

    const securityConfig = getSecurityConfig();

    if (securityConfig.mode === "off" || !securityConfig.providers.rules) {
      return serveLanding(request, {
        requestId,
        reason: "security_off",
        engineVersion: securityConfig.version
      });
    }

    // Device Fingerprint Security Layer v1 — cookie gate (before IPinfo)
    if (securityConfig.providers.fingerprint !== false) {
      const fpGate = evaluateFingerprintCookies(request);
      if (fpGate.blocked && isEnforcementEnabled(securityConfig)) {
        try {
          await logVisit(
            {
              timestamp: new Date().toISOString(),
              method: request.method,
              path: request.nextUrl.pathname,
              ip: extractClientIP(request),
              requestId,
              attribution,
              rulesResult: {
                decision: "block",
                allow: false,
                matchedRules: ["device_fingerprint_blacklist"],
                reason: "device_fingerprint_blacklist",
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

        if (hasAdClickId(attribution)) {
          keepAlive(
            event,
            sendCircuitSignal({
              requestId,
              ip: extractClientIP(request),
              asn: null,
              country: null,
              reason: "device_fingerprint_blacklist",
              path: request.nextUrl.pathname,
              clickId: primaryClickId(attribution)
            })
          );
        }

        return createForbiddenResponse({
          requestId,
          engineVersion: securityConfig.version,
          blockType: "fingerprint",
          country: null,
          reason: "device_fingerprint_blacklist"
        });
      }
    }

    const ipResult = await checkIP(request, { config: securityConfig });

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
          requestId,
          attribution
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
      if (hasAdClickId(attribution)) {
        keepAlive(
          event,
          sendCircuitSignal({
            requestId,
            ip: ipResult.ip,
            asn: ipResult.info && ipResult.info.asn,
            country:
              rulesResult.country || (ipResult.info && ipResult.info.country),
            reason: rulesResult.reason,
            path: request.nextUrl.pathname,
            clickId: primaryClickId(attribution)
          })
        );
      }

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
