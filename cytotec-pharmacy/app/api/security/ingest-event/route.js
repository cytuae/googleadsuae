/**
 * POST /api/security/ingest-event
 * Internal ingest for middleware / fingerprint (not public).
 * Auth: header x-security-ingest-secret === SECURITY_INGEST_SECRET
 *   or SECURITY_ADMIN_PASSWORD when ingest secret unset.
 */

import { NextResponse } from "next/server";
import { appendSecurityEvent } from "../../../../security/event-store";
import { getAdminPassword } from "../../../../security/admin-auth";

export const runtime = "nodejs";

function ingestSecret() {
  return (
    String(process.env.SECURITY_INGEST_SECRET || "").trim() ||
    getAdminPassword()
  );
}

export async function POST(request) {
  try {
    const expected = ingestSecret();
    if (!expected) {
      return NextResponse.json({ ok: false }, { status: 503 });
    }

    const got = request.headers.get("x-security-ingest-secret") || "";
    if (got !== expected) {
      return NextResponse.json({ ok: false }, { status: 401 });
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return NextResponse.json({ ok: false, error: "invalid_json" }, { status: 400 });
    }

    // Fire-and-forget style but await briefly so serverless doesn't freeze early
    const result = await appendSecurityEvent(body || {});
    return NextResponse.json({ ok: result.ok, error: result.error || null });
  } catch {
    return NextResponse.json({ ok: false, error: "fail_open" }, { status: 200 });
  }
}
