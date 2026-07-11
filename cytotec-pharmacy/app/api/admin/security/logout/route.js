/**
 * POST /api/admin/security/logout
 */

import { NextResponse } from "next/server";
import { ADMIN_COOKIE } from "../../../../../security/admin-auth";

export const runtime = "nodejs";

export async function POST() {
  const res = NextResponse.json({ ok: true });
  res.cookies.set(ADMIN_COOKIE, "", {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    path: "/",
    maxAge: 0
  });
  return res;
}
