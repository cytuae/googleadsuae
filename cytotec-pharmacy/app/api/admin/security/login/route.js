/**
 * POST /api/admin/security/login
 */

import { NextResponse } from "next/server";
import {
  ADMIN_COOKIE,
  ADMIN_COOKIE_OPTIONS,
  createAdminSessionToken,
  isAdminConfigured,
  verifyAdminPassword
} from "../../../../../security/admin-auth";

export const runtime = "nodejs";

export async function POST(request) {
  try {
    if (!isAdminConfigured()) {
      return NextResponse.json(
        { ok: false, error: "admin_not_configured" },
        { status: 503 }
      );
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return NextResponse.json({ ok: false, error: "invalid_json" }, { status: 400 });
    }

    const password = body && body.password != null ? String(body.password) : "";
    if (!verifyAdminPassword(password)) {
      return NextResponse.json({ ok: false, error: "invalid_password" }, { status: 401 });
    }

    const res = NextResponse.json({ ok: true });
    res.cookies.set(ADMIN_COOKIE, createAdminSessionToken(), ADMIN_COOKIE_OPTIONS);
    return res;
  } catch {
    return NextResponse.json({ ok: false, error: "fail_open" }, { status: 200 });
  }
}
