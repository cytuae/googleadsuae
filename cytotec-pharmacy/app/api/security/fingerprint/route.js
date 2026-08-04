/**
 * POST /api/security/fingerprint
 * ------------------------------
 * Receives FingerprintJS visitorId + device signals.
 * IP is taken only from trusted Vercel / proxy headers (never from the body).
 *
 * Blacklisted visitorIds:
 *   VISITOR_BLOCK_MODE=monitor + UAE residential → 200 flagged (WhatsApp OK)
 *   otherwise → 403 blocked_visitor_id
 *
 * Never exposes secrets. Never returns HTTP 500.
 */

import { NextResponse } from "next/server";
import { checkIP, extractClientIP } from "../../../../security/ipinfo";
import { isFingerprintBlacklisted } from "../../../../security/blacklists";
import { getSecurityConfig } from "../../../../security/config";
import { resolveSuspiciousVisitorDecision } from "../../../../security/visitor-block";
import {
  appendSecurityEvent,
  inferBrowser,
  inferDevice
} from "../../../../security/event-store";

export const runtime = "nodejs";

const COOKIE_BASE = {
  httpOnly: true,
  secure: true,
  sameSite: "lax",
  path: "/",
  maxAge: 31536000
};

/**
 * @param {unknown} value
 * @param {number} max
 * @returns {string|null}
 */
function asTrimmedString(value, max) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  return trimmed.slice(0, max);
}

/**
 * @param {unknown} value
 * @returns {number|null}
 */
function asFiniteNumber(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  return value;
}

/**
 * @param {unknown} body
 * @returns {{ ok: true, data: Object } | { ok: false, error: string }}
 */
function validateBody(body) {
  if (!body || typeof body !== "object") {
    return { ok: false, error: "invalid_body" };
  }

  const visitorId = asTrimmedString(
    /** @type {Record<string, unknown>} */ (body).visitorId,
    128
  );
  if (!visitorId || !/^[a-zA-Z0-9_-]+$/.test(visitorId)) {
    return { ok: false, error: "invalid_visitor_id" };
  }

  const b = /** @type {Record<string, unknown>} */ (body);
  const screenWidth = asFiniteNumber(b.screenWidth) ?? 0;
  const screenHeight = asFiniteNumber(b.screenHeight) ?? 0;

  return {
    ok: true,
    data: {
      visitorId,
      userAgent: asTrimmedString(b.userAgent, 512) || "",
      platform: asTrimmedString(b.platform, 128) || "",
      language: asTrimmedString(b.language, 64) || "",
      timezone: asTrimmedString(b.timezone, 128) || "",
      screenWidth,
      screenHeight,
      devicePixelRatio: asFiniteNumber(b.devicePixelRatio),
      touchSupport: b.touchSupport === true,
      hardwareConcurrency: asFiniteNumber(b.hardwareConcurrency) ?? 0,
      deviceMemory:
        typeof b.deviceMemory === "number" && Number.isFinite(b.deviceMemory)
          ? b.deviceMemory
          : null,
      pathname: asTrimmedString(b.pathname, 512) || "/",
      gclid: asTrimmedString(b.gclid, 256),
      gbraid: asTrimmedString(b.gbraid, 256),
      wbraid: asTrimmedString(b.wbraid, 256),
      utm_source: asTrimmedString(b.utm_source, 256),
      utm_medium: asTrimmedString(b.utm_medium, 256),
      utm_campaign: asTrimmedString(b.utm_campaign, 256),
      utm_term: asTrimmedString(b.utm_term, 256),
      utm_content: asTrimmedString(b.utm_content, 256)
    }
  };
}

/**
 * @param {import('next/server').NextRequest} request
 */
export async function POST(request) {
  try {
    let body;
    try {
      body = await request.json();
    } catch {
      return NextResponse.json(
        { ok: false, blocked: false, error: "invalid_json" },
        { status: 400 }
      );
    }

    const validated = validateBody(body);
    if (!validated.ok) {
      return NextResponse.json(
        { ok: false, blocked: false, error: validated.error },
        { status: 400 }
      );
    }

    const data = validated.data;
    const ip = extractClientIP(request);
    const securityConfig = getSecurityConfig();
    const timestamp = new Date().toISOString();
    const screen = `${data.screenWidth}x${data.screenHeight}`;

    // Permanent visitorId denylist — enrich with IPinfo for monitor mode
    if (isFingerprintBlacklisted(data.visitorId)) {
      let ipInfo = null;
      try {
        const ipResult = await checkIP(request, { config: securityConfig });
        ipInfo = ipResult.info || null;
      } catch {
        ipInfo = null;
      }

      const decision = resolveSuspiciousVisitorDecision({
        mode: securityConfig.visitorBlockMode,
        ipInfo,
        visitorId: data.visitorId
      });

      if (decision.monitorOnly) {
        const eventPayload = {
          event: "DEVICE_FINGERPRINT",
          timestamp,
          visitorId: data.visitorId,
          ip: ip === "unknown" ? null : ip,
          blocked: false,
          flagged: true,
          reason: "monitored_suspicious_visitor",
          userAgent: data.userAgent,
          platform: data.platform,
          language: data.language,
          timezone: data.timezone,
          screen,
          devicePixelRatio: data.devicePixelRatio,
          touchSupport: data.touchSupport,
          hardwareConcurrency: data.hardwareConcurrency,
          deviceMemory: data.deviceMemory,
          pathname: data.pathname,
          gclid: data.gclid,
          gbraid: data.gbraid,
          wbraid: data.wbraid,
          browser: inferBrowser(data.userAgent),
          device: inferDevice(data),
          provider: ipInfo?.company || null,
          company: ipInfo?.company || null,
          asn: ipInfo?.asn || null,
          country: ipInfo?.country || "AE"
        };

        console.info(JSON.stringify(eventPayload));

        const syncMode = String(
          process.env.SECURITY_EVENT_SYNC || "all"
        ).toLowerCase();
        if (syncMode !== "off") {
          try {
            await appendSecurityEvent(eventPayload);
          } catch {
            // ignore
          }
        }

        const res = NextResponse.json(
          {
            ok: true,
            blocked: false,
            flagged: true,
            reason: "monitored_suspicious_visitor",
            whatsappAllowed: true
          },
          { status: 200 }
        );
        res.cookies.set("device_fingerprint", data.visitorId, COOKIE_BASE);
        // Clear any prior hard-block cookie so UAE residents recover
        res.cookies.set("security_blocked", "", { ...COOKIE_BASE, maxAge: 0 });
        return res;
      }

      const eventPayload = {
        event: "DEVICE_FINGERPRINT",
        timestamp,
        visitorId: data.visitorId,
        ip: ip === "unknown" ? null : ip,
        blocked: true,
        flagged: false,
        reason: "blocked_visitor_id",
        userAgent: data.userAgent,
        platform: data.platform,
        language: data.language,
        timezone: data.timezone,
        screen,
        devicePixelRatio: data.devicePixelRatio,
        touchSupport: data.touchSupport,
        hardwareConcurrency: data.hardwareConcurrency,
        deviceMemory: data.deviceMemory,
        pathname: data.pathname,
        gclid: data.gclid,
        gbraid: data.gbraid,
        wbraid: data.wbraid,
        browser: inferBrowser(data.userAgent),
        device: inferDevice(data),
        provider: ipInfo?.company || null,
        company: ipInfo?.company || null,
        asn: ipInfo?.asn || null,
        country: ipInfo?.country || null
      };

      console.info(JSON.stringify(eventPayload));

      const syncMode = String(
        process.env.SECURITY_EVENT_SYNC || "all"
      ).toLowerCase();
      if (syncMode !== "off") {
        try {
          await appendSecurityEvent(eventPayload);
        } catch {
          // ignore
        }
      }

      const res = NextResponse.json(
        { ok: true, blocked: true, reason: "blocked_visitor_id" },
        { status: 403 }
      );
      res.cookies.set("security_blocked", "1", COOKIE_BASE);
      res.cookies.set("device_fingerprint", data.visitorId, COOKIE_BASE);
      return res;
    }

    const eventPayload = {
      event: "DEVICE_FINGERPRINT",
      timestamp,
      visitorId: data.visitorId,
      ip: ip === "unknown" ? null : ip,
      blocked: false,
      reason: "fingerprint_ok",
      userAgent: data.userAgent,
      platform: data.platform,
      language: data.language,
      timezone: data.timezone,
      screen,
      devicePixelRatio: data.devicePixelRatio,
      touchSupport: data.touchSupport,
      hardwareConcurrency: data.hardwareConcurrency,
      deviceMemory: data.deviceMemory,
      pathname: data.pathname,
      gclid: data.gclid,
      gbraid: data.gbraid,
      wbraid: data.wbraid,
      browser: inferBrowser(data.userAgent),
      device: inferDevice(data),
      provider: null,
      company: null,
      asn: null,
      country: null
    };

    console.log(JSON.stringify(eventPayload));

    const syncMode = String(process.env.SECURITY_EVENT_SYNC || "all").toLowerCase();
    if (syncMode === "all") {
      void appendSecurityEvent(eventPayload).catch(() => {});
    }

    const res = NextResponse.json(
      { ok: true, blocked: false },
      { status: 200 }
    );
    res.cookies.set("device_fingerprint", data.visitorId, COOKIE_BASE);
    return res;
  } catch (error) {
    console.error("[fingerprint:api:error]", {
      message: error && error.message ? error.message : String(error)
    });
    // Fail-safe: never HTTP 500
    return NextResponse.json(
      { ok: false, blocked: false, reason: "fail_open" },
      { status: 200 }
    );
  }
}

export async function GET() {
  return NextResponse.json({ ok: false, error: "method_not_allowed" }, { status: 405 });
}
