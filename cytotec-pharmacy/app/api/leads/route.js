/**
 * POST /api/leads
 * ---------------
 * Landing-page lead form (phone, emirate).
 * Logs to Vercel Runtime Logs + optional security event store.
 * Never returns HTTP 500. Does not change page design.
 */

import { NextResponse } from "next/server";
import { extractClientIP } from "../../../security/ipinfo";
import { appendSecurityEvent } from "../../../security/event-store";

export const runtime = "nodejs";

const EMIRATES = new Set([
  "دبي",
  "أبوظبي",
  "الشارقة",
  "عجمان",
  "رأس الخيمة",
  "الفجيرة",
  "أم القيوين"
]);

/**
 * @param {unknown} value
 * @param {number} max
 * @returns {string}
 */
function asTrimmedString(value, max) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, max);
}

/**
 * @param {string} phone
 * @returns {string}
 */
function digitsOnly(phone) {
  return phone.replace(/\D/g, "");
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
        { ok: false, error: "طلب غير صالح." },
        { status: 400 }
      );
    }

    const telephoneRaw = asTrimmedString(
      body?.telephone ?? body?.phone,
      40
    );
    const telephone = digitsOnly(telephoneRaw);
    const emirate = asTrimmedString(body?.emirate, 64);

    if (telephone.length < 8) {
      return NextResponse.json(
        { ok: false, error: "يرجى إدخال رقم هاتف صحيح." },
        { status: 400 }
      );
    }
    if (!emirate || !EMIRATES.has(emirate)) {
      return NextResponse.json(
        { ok: false, error: "يرجى اختيار الإمارة." },
        { status: 400 }
      );
    }

    const ip = extractClientIP(request);
    const timestamp = new Date().toISOString();
    const eventPayload = {
      event: "LEAD_FORM",
      timestamp,
      telephone,
      emirate,
      ip: ip === "unknown" ? null : ip,
      pathname: "/index.html",
      userAgent: request.headers.get("user-agent") || "",
      blocked: false,
      reason: "lead_form_ok",
      gclid: asTrimmedString(body?.gclid, 256) || null,
      gbraid: asTrimmedString(body?.gbraid, 256) || null,
      wbraid: asTrimmedString(body?.wbraid, 256) || null
    };

    console.info(JSON.stringify(eventPayload));

    try {
      await appendSecurityEvent(eventPayload);
    } catch {
      // ignore store failures — lead already logged
    }

    return NextResponse.json({ ok: true }, { status: 200 });
  } catch (error) {
    console.error("[leads:api:error]", {
      message: error && error.message ? error.message : String(error)
    });
    return NextResponse.json(
      { ok: false, error: "تعذّر الإرسال. حاولي مرة أخرى." },
      { status: 200 }
    );
  }
}

export async function GET() {
  return NextResponse.json(
    { ok: false, error: "method_not_allowed" },
    { status: 405 }
  );
}
