/**
 * Edge security middleware — Strict Security Gate v1
 * --------------------------------------------------
 * Inspect HTML/document visitors via IPinfo, enforce anonymity/hosting
 * blocks, keep geo allowlist, fail-open on errors, never expose token.
 *
 * Static assets and Next internals are excluded from the matcher.
 */

import { NextResponse } from "next/server";
import { getSecurityConfig, isEnforcementEnabled } from "./security/config";
import { checkIP, extractClientIP } from "./security/ipinfo";
import { applyRules } from "./security/rules";
import { logVisit } from "./security/logger";
import { createForbiddenResponse } from "./security/responses";
import { isGoogleAdsOrSearchBot } from "./security/bots";

export const config = {
  matcher: [
    "/",
    "/index.html",
    "/((?!_next(?:/|$)|assets(?:/|$)|favicon\\.ico$|robots\\.txt$|sitemap\\.xml$|.*\\.(?:ico|png|jpe?g|gif|webp|svg|avif|css|js|mjs|map|woff2?|ttf|eot|txt)$).*)"
  ]
};

/**
 * @param {import('next/server').NextRequest} request
 * @param {{ requestId?: string, reason?: string, engineVersion?: string }} [meta]
 * @returns {import('next/server').NextResponse}
 */
function serveLanding(request, meta = {}) {
  const url = request.nextUrl.clone();
  /** @type {Record<string, string>} */
  const headers = {
    "x-security-engine": meta.engineVersion || "1.5.0-strict-gate-v1",
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
    // Google Ads / Search crawlers — never block (Quality Score / Ads bots)
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
      engineVersion: "1.5.0-strict-gate-v1"
    });
  }
}
