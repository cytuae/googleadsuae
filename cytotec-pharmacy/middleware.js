/**
 * Vercel Edge Middleware — Security Engine
 * ========================================
 * Runs on every matched request BEFORE the page/asset is served.
 *
 * Pipeline:
 *   1. Load config
 *   2. IP intelligence          → checkIP() / getIPInfo()
 *   3. Fingerprint signals      → checkFingerprint()
 *   4. Rules / decision engine  → applyRules()
 *   5. Structured visit logging → logVisit()
 *   6. Continue (no blocking in this phase)
 *
 * Current policy: ALLOW ALL. IPinfo enrichment is monitor-only.
 */

import { NextResponse } from "next/server";
import {
  getSecurityConfig,
  isEnforcementEnabled,
  isDevelopment,
  checkIP,
  checkFingerprint,
  applyRules,
  logVisit
} from "./security/index.js";

/**
 * @param {import('next/server').NextRequest} request
 */
export async function middleware(request) {
  const requestId =
    request.headers.get("x-request-id") ||
    request.headers.get("x-vercel-id") ||
    crypto.randomUUID();

  // -------------------------------------------------------------------------
  // STAGE 0 — Configuration
  // -------------------------------------------------------------------------
  const config = getSecurityConfig();

  /** @type {Record<string, unknown>} */
  const ctx = {
    config,
    requestId,
    startedAt: Date.now()
  };

  // -------------------------------------------------------------------------
  // STAGE 1 — IP intelligence (IPinfo)
  // Enriches the request; never blocks.
  // -------------------------------------------------------------------------
  const ipResult = await checkIP(request, ctx);
  ctx.ipResult = ipResult;

  // Development-only visibility into normalized IPinfo payload
  if (isDevelopment()) {
    console.log("[security:ipinfo]", {
      requestId,
      ok: ipResult.ok,
      reason: ipResult.reason,
      cached: ipResult.cached,
      info: ipResult.info
    });
  }

  // -------------------------------------------------------------------------
  // STAGE 2 — Fingerprint signals (scaffold)
  // -------------------------------------------------------------------------
  const fingerprintResult = await checkFingerprint(request, {
    ...ctx,
    ipResult
  });
  ctx.fingerprintResult = fingerprintResult;

  // -------------------------------------------------------------------------
  // STAGE 3 — Rules engine (scaffold — always allow)
  // -------------------------------------------------------------------------
  const rulesResult = await applyRules({
    request,
    config,
    ipResult,
    fingerprintResult
  });
  ctx.rulesResult = rulesResult;

  // -------------------------------------------------------------------------
  // STAGE 4 — Visit logging (scaffold)
  // -------------------------------------------------------------------------
  if (config.providers.logger) {
    try {
      await logVisit(
        {
          timestamp: new Date().toISOString(),
          method: request.method,
          path: request.nextUrl?.pathname || new URL(request.url).pathname,
          ip: ipResult.ip,
          ipResult,
          fingerprintResult,
          rulesResult,
          requestId
        },
        { config }
      );
    } catch {
      // Availability > telemetry
    }
  }

  // -------------------------------------------------------------------------
  // STAGE 5 — Enforcement gate (disabled)
  // -------------------------------------------------------------------------
  const shouldBlock =
    isEnforcementEnabled(config) && rulesResult.allow === false;

  if (shouldBlock) {
    return new NextResponse("Forbidden", {
      status: 403,
      headers: {
        "x-security-engine": config.version,
        "x-request-id": requestId
      }
    });
  }

  // -------------------------------------------------------------------------
  // STAGE 6 — Continue / rewrite to static landing page
  // -------------------------------------------------------------------------
  const pathname = request.nextUrl?.pathname || new URL(request.url).pathname;
  const response =
    pathname === "/" || pathname === ""
      ? NextResponse.rewrite(new URL("/index.html", request.url))
      : NextResponse.next();

  response.headers.set("x-security-engine", config.version);
  response.headers.set("x-security-mode", config.mode);
  response.headers.set("x-security-decision", rulesResult.decision || "allow");
  response.headers.set("x-request-id", requestId);

  if (ipResult.info?.country) {
    response.headers.set("x-security-country", String(ipResult.info.country));
  }

  return response;
}

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|_vercel|.*\\.(?:ico|png|jpg|jpeg|gif|webp|svg|css|js|map|txt|xml|woff2?)$).*)"
  ]
};
