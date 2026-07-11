/**
 * Vercel Edge Middleware — Security Engine
 * ========================================
 * Pipeline:
 *   1. Config
 *   2. IPinfo enrichment
 *   3. Fingerprint (scaffold)
 *   4. Rules (country block: JO)
 *   5. Logging
 *   6. Allow or 403 Forbidden
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
import { createForbiddenResponse } from "./security/responses.js";

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
  // -------------------------------------------------------------------------
  const ipResult = await checkIP(request, ctx);
  ctx.ipResult = ipResult;

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
  // STAGE 2 — Fingerprint signals (scaffold / disabled)
  // -------------------------------------------------------------------------
  const fingerprintResult = await checkFingerprint(request, {
    ...ctx,
    ipResult
  });
  ctx.fingerprintResult = fingerprintResult;

  // -------------------------------------------------------------------------
  // STAGE 3 — Rules engine
  // -------------------------------------------------------------------------
  const rulesResult = await applyRules({
    request,
    config,
    ipResult,
    fingerprintResult
  });
  ctx.rulesResult = rulesResult;

  // -------------------------------------------------------------------------
  // STAGE 4 — Visit logging
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
  // STAGE 5 — Enforcement gate
  // -------------------------------------------------------------------------
  const shouldBlock =
    isEnforcementEnabled(config) && rulesResult.allow === false;

  if (shouldBlock) {
    return createForbiddenResponse({
      requestId,
      engineVersion: config.version,
      blockType: rulesResult.blockType || "country",
      country: rulesResult.country || null
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

  if (rulesResult.country) {
    response.headers.set("x-security-country", String(rulesResult.country));
  }

  return response;
}

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|_vercel|.*\\.(?:ico|png|jpg|jpeg|gif|webp|svg|css|js|map|txt|xml|woff2?)$).*)"
  ]
};
