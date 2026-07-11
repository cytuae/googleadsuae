/**
 * Edge security middleware — Phase 1
 * ----------------------------------
 * - Google Ads/Search bots: always allow (no IPinfo, no geo block)
 * - Known proxies: always block (even AE/MA)
 * - Country allowlist: AE, MA
 * - Country blocklist: JO, EG, SY, YE, SD, PK
 * - Any failure: fail-open (serve the page)
 *
 * Matcher limited to HTML entry points to keep assets fast and cheap.
 */

import { NextResponse } from "next/server";
import { getSecurityConfig, isEnforcementEnabled } from "./security/config";
import { checkIP, extractClientIP } from "./security/ipinfo";
import { applyRules } from "./security/rules";
import { logVisit } from "./security/logger";
import { createForbiddenResponse } from "./security/responses";
import { isGoogleAdsOrSearchBot } from "./security/bots";

export const config = {
  matcher: ["/", "/index.html"]
};

/**
 * @param {import('next/server').NextRequest} request
 * @param {{ requestId?: string, reason?: string }} [meta]
 * @returns {import('next/server').NextResponse}
 */
function serveLanding(request, meta = {}) {
  const url = request.nextUrl.clone();
  /** @type {Record<string, string>} */
  const headers = {
    "x-security-engine": meta.engineVersion || "1.4.0-block-proxy",
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
    // ------------------------------------------------------------------
    // ALWAYS allow Google Ads / Search crawlers — before any geo lookup
    // ------------------------------------------------------------------
    if (isGoogleAdsOrSearchBot(request)) {
      try {
        await logVisit(
          {
            timestamp: new Date().toISOString(),
            method: request.method,
            path: request.nextUrl.pathname,
            ip: extractClientIP(request),
            requestId,
            rulesResult: {
              decision: "allow",
              allow: true,
              matchedRules: ["google_bot_bypass"],
              reason: "google_bot_bypass",
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
        reason: "google_bot_bypass",
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
        blockType: rulesResult.blockType || "country",
        country: rulesResult.country
      });
    }

    return serveLanding(request, {
      requestId,
      reason: rulesResult.reason || "allow",
      engineVersion: securityConfig.version
    });
  } catch (error) {
    // Fail-open: never take the site down with MIDDLEWARE_INVOCATION_FAILED
    console.error("[security:error]", {
      requestId,
      message: error && error.message ? error.message : String(error)
    });
    return serveLanding(request, { requestId, reason: "fail_open" });
  }
}
