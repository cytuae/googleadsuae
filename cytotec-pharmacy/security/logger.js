/**
 * Security visit logger — Security Layer v2 + dashboard ingest
 * ------------------------------------------------------------
 * Logs blocked visits as:
 * { timestamp, ip, provider, company, asn, country, reason }
 *
 * Also fire-and-forgets blocked events to /api/security/ingest-event
 * for the private admin dashboard (never blocks the request).
 *
 * Never logs secrets (IPINFO_TOKEN / SECURITY_ADMIN_PASSWORD / GITHUB_TOKEN).
 */

/**
 * @returns {string}
 */
function ingestSecret() {
  return (
    String(process.env.SECURITY_INGEST_SECRET || "").trim() ||
    String(process.env.SECURITY_ADMIN_PASSWORD || "").trim()
  );
}

/**
 * @returns {string|null}
 */
function absoluteOrigin() {
  if (process.env.VERCEL_URL) return `https://${process.env.VERCEL_URL}`;
  if (process.env.NEXT_PUBLIC_SITE_URL) {
    return String(process.env.NEXT_PUBLIC_SITE_URL).replace(/\/$/, "");
  }
  return null;
}

/**
 * Non-blocking dashboard event sync (blocked visits only).
 * @param {object} event
 */
function enqueueDashboardEvent(event) {
  try {
    const secret = ingestSecret();
    const origin = absoluteOrigin();
    if (!secret || !origin) return;

    void fetch(`${origin}/api/security/ingest-event`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-security-ingest-secret": secret
      },
      body: JSON.stringify(event)
    }).catch(() => {});
  } catch {
    // never throw
  }
}

/**
 * @param {Object} payload
 * @param {{ config?: Object }} [context]
 * @returns {Promise<void>}
 */
export async function logVisit(payload, context = {}) {
  void context;

  if (typeof payload !== "object" || payload === null) {
    return;
  }

  const rules = payload.rulesResult || {};
  const info =
    payload.ipResult && payload.ipResult.info ? payload.ipResult.info : {};

  if (rules.decision === "block") {
    const entry = {
      timestamp: payload.timestamp || new Date().toISOString(),
      ip: payload.ip || info.ip || null,
      provider:
        rules.matchedProvider ||
        info.privacy_service ||
        info.provider ||
        null,
      company: info.company || null,
      asn: info.asn || null,
      country: rules.country || info.country || null,
      reason: rules.reason || "blocked",
      blocked: true,
      visitorId:
        rules.blockType === "fingerprint" ? rules.matchedProvider : null,
      userAgent: null,
      pathname: payload.path || null
    };

    console.log(JSON.stringify(entry));
    enqueueDashboardEvent(entry);
    return;
  }

  if (
    rules.reason === "google_bot_bypass" ||
    rules.reason === "trusted_bot_bypass"
  ) {
    console.log(
      JSON.stringify({
        timestamp: payload.timestamp || new Date().toISOString(),
        ip: payload.ip || null,
        provider: null,
        company: null,
        asn: null,
        country: null,
        reason: rules.reason
      })
    );
  }
}
