/**
 * POST /api/leads
 * ---------------
 * Landing-page lead form (phone, emirate).
 * Validates → POSTs to Google Apps Script (Sheets) → only then returns ok.
 * Also logs to Vercel Runtime Logs + optional security event store.
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

const DEFAULT_SHEETS_WEBAPP_URL =
  "https://script.google.com/macros/s/AKfycbzzl3IbAnkuLq9SBOcjS5Utvqe6nqKKYO_jMpZq9dCQa1Qkfc0EzCSQXxgiCVkha66EvA/exec";

const SHEETS_TIMEOUT_MS = 15000;

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
 * @returns {string}
 */
function sheetsWebAppUrl() {
  const fromEnv = asTrimmedString(process.env.GOOGLE_SHEETS_WEBAPP_URL, 500);
  return fromEnv || DEFAULT_SHEETS_WEBAPP_URL;
}

/**
 * POST lead to Google Apps Script Web App (writes Google Sheet).
 * @param {{ phone: string, emirate: string }} lead
 * @returns {Promise<{ ok: true } | { ok: false, error: string }>}
 */
async function postLeadToGoogleSheets(lead) {
  const url = sheetsWebAppUrl();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), SHEETS_TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        phone: lead.phone,
        emirate: lead.emirate,
        source: "Google Ads"
      }),
      redirect: "follow",
      signal: controller.signal
    });

    const text = await res.text().catch(() => "");
    let parsed = null;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      parsed = null;
    }

    if (!res.ok) {
      return {
        ok: false,
        error: `sheets_http_${res.status}`
      };
    }

    if (
      parsed &&
      typeof parsed === "object" &&
      (parsed.ok === false ||
        parsed.success === false ||
        parsed.error ||
        parsed.result === "error")
    ) {
      return {
        ok: false,
        error:
          typeof parsed.error === "string"
            ? parsed.error
            : "sheets_response_error"
      };
    }

    return { ok: true };
  } catch (error) {
    const message =
      error && error.name === "AbortError"
        ? "sheets_timeout"
        : error && error.message
          ? error.message
          : String(error);
    return { ok: false, error: message };
  } finally {
    clearTimeout(timer);
  }
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

    const sheetsResult = await postLeadToGoogleSheets({
      phone: telephone,
      emirate
    });

    if (!sheetsResult.ok) {
      console.error(
        JSON.stringify({
          event: "LEAD_FORM_SHEETS_ERROR",
          timestamp: new Date().toISOString(),
          telephone,
          emirate,
          error: sheetsResult.error
        })
      );
      return NextResponse.json(
        { ok: false, error: "تعذّر الإرسال. حاولي مرة أخرى." },
        { status: 200 }
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
      // ignore store failures — Sheet write already succeeded
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
