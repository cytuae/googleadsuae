/**
 * POST /api/security/whatsapp-click
 * ---------------------------------
 * Logs WHATSAPP_CLICK with server-derived IP / UA / IPinfo enrichment.
 * Never blocks the visitor. Always returns 204 (fail-open).
 * Does not trust client-supplied IP.
 */

import { NextResponse } from "next/server";
import { getSecurityConfig } from "../../../../security/config";
import { checkIP, extractClientIP } from "../../../../security/ipinfo";
import { inferBrowser, inferDevice } from "../../../../security/event-store";

export const runtime = "nodejs";

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
 * @returns {string}
 */
function newEventId() {
  try {
    if (typeof crypto !== "undefined" && crypto.randomUUID) {
      return crypto.randomUUID();
    }
  } catch {
    // ignore
  }
  return `wa_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
}

/**
 * @param {import('next/server').NextRequest} request
 */
export async function POST(request) {
  try {
    let body = {};
    try {
      const parsed = await request.json();
      if (parsed && typeof parsed === "object") body = parsed;
    } catch {
      body = {};
    }

    const b = /** @type {Record<string, unknown>} */ (body);
    const ip = extractClientIP(request);
    const userAgent =
      request.headers.get("user-agent") ||
      asTrimmedString(b.userAgent, 512) ||
      "";

    /** @type {Record<string, unknown>|null} */
    let info = null;
    try {
      const ipResult = await checkIP(request, {
        config: getSecurityConfig()
      });
      if (ipResult && ipResult.info) info = ipResult.info;
    } catch {
      info = null;
    }

    const screen =
      asTrimmedString(b.screen, 64) ||
      (typeof b.screenWidth === "number" && typeof b.screenHeight === "number"
        ? `${b.screenWidth}x${b.screenHeight}`
        : null);

    const clientDevice = asTrimmedString(b.device, 64);
    const clientBrowser = asTrimmedString(b.browser, 64);

    const eventPayload = {
      event: "WHATSAPP_CLICK",
      timestamp: asTrimmedString(b.timestamp, 64) || new Date().toISOString(),
      eventId: asTrimmedString(b.eventId, 128) || newEventId(),
      visitorId: asTrimmedString(b.visitorId, 128),
      ip: ip === "unknown" ? null : ip,
      gclid: asTrimmedString(b.gclid, 256),
      gbraid: asTrimmedString(b.gbraid, 256),
      wbraid: asTrimmedString(b.wbraid, 256),
      pathname: asTrimmedString(b.pathname, 512) || "/",
      buttonLocation: asTrimmedString(b.buttonLocation, 64) || "whatsapp",
      userAgent: userAgent ? String(userAgent).slice(0, 512) : null,
      device:
        clientDevice ||
        inferDevice({
          userAgent,
          platform: asTrimmedString(b.platform, 128),
          touchSupport: b.touchSupport === true
        }),
      browser: clientBrowser || inferBrowser(userAgent),
      country: info && info.country ? info.country : null,
      provider:
        (info && (info.privacy_service || info.provider)) || null,
      company: (info && info.company) || null,
      asn: (info && info.asn) || null,
      referrer: asTrimmedString(b.referrer, 512),
      timezone: asTrimmedString(b.timezone, 128),
      screen,
      blocked: false
    };

    console.info(JSON.stringify(eventPayload));

    return new NextResponse(null, { status: 204 });
  } catch (error) {
    console.error("[whatsapp-click:api:error]", {
      message: error && error.message ? error.message : String(error)
    });
    return new NextResponse(null, { status: 204 });
  }
}

export async function GET() {
  return new NextResponse(null, { status: 405 });
}
