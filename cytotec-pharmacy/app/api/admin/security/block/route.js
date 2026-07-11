/**
 * POST /api/admin/security/block
 * Body: { type: 'ip'|'fingerprint'|'asn'|'provider', value: string }
 * Updates the corresponding security/*-blacklist.json via GitHub.
 */

import { NextResponse } from "next/server";
import { isAdminAuthenticated } from "../../../../../security/admin-auth";
import { addToBlacklist, getGithubConfig } from "../../../../../security/github-files";
import { appendSecurityEvent } from "../../../../../security/event-store";

export const runtime = "nodejs";

const TYPES = new Set(["ip", "fingerprint", "asn", "provider"]);

export async function POST(request) {
  try {
    if (!isAdminAuthenticated(request)) {
      return NextResponse.json({ ok: false, error: "unauthorized" }, { status: 401 });
    }

    if (!getGithubConfig()) {
      return NextResponse.json(
        {
          ok: false,
          error: "github_not_configured",
          message:
            "Set GITHUB_TOKEN (repo contents:write) on Vercel to update blacklists automatically."
        },
        { status: 503 }
      );
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return NextResponse.json({ ok: false, error: "invalid_json" }, { status: 400 });
    }

    const type = body && body.type != null ? String(body.type) : "";
    const value = body && body.value != null ? String(body.value).trim() : "";

    if (!TYPES.has(type) || !value) {
      return NextResponse.json({ ok: false, error: "invalid_request" }, { status: 400 });
    }

    if (type === "ip" && !/^\d{1,3}(?:\.\d{1,3}){3}$|^[0-9a-fA-F:]+$/.test(value)) {
      return NextResponse.json({ ok: false, error: "invalid_ip" }, { status: 400 });
    }

    const result = await addToBlacklist(type, value);
    if (!result.ok) {
      return NextResponse.json(
        { ok: false, error: result.error || "block_failed" },
        { status: 502 }
      );
    }

    // Record admin action in event log (best-effort)
    void appendSecurityEvent({
      timestamp: new Date().toISOString(),
      blocked: true,
      reason: `admin_block_${type}`,
      ip: type === "ip" ? value : null,
      visitorId: type === "fingerprint" ? value : null,
      provider: type === "provider" ? value : null,
      asn: type === "asn" ? value : null
    });

    return NextResponse.json({
      ok: true,
      already: Boolean(result.already),
      type,
      value,
      message: result.already
        ? "Already on blacklist"
        : "Blacklist updated — Vercel will redeploy shortly"
    });
  } catch {
    return NextResponse.json({ ok: false, error: "fail_open" }, { status: 200 });
  }
}
