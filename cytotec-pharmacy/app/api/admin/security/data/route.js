/**
 * GET /api/admin/security/data
 * Returns blacklist snapshots + recent events for the dashboard.
 */

import { NextResponse } from "next/server";
import { isAdminAuthenticated } from "../../../../../security/admin-auth";
import { getGithubConfig } from "../../../../../security/github-files";
import { loadEventsForDashboard } from "../../../../../security/event-store";
import { loadIpBlacklist, loadProviderBlacklist, loadAsnBlacklist, loadFingerprintBlacklist } from "../../../../../security/blacklists";
import {
  getGithubJsonFile,
  securityFilePath
} from "../../../../../security/github-files";

export const runtime = "nodejs";

/**
 * @param {string} type
 * @returns {Promise<string[]>}
 */
async function loadLiveList(type) {
  if (!getGithubConfig()) {
    if (type === "ip") return loadIpBlacklist();
    if (type === "provider") return loadProviderBlacklist();
    if (type === "asn") return loadAsnBlacklist();
    if (type === "fingerprint") return loadFingerprintBlacklist();
    return [];
  }

  try {
    if (type === "fingerprint") {
      const remote = await getGithubJsonFile(
        securityFilePath("fingerprint-blacklist.json")
      );
      if (remote.ok && Array.isArray(remote.json)) {
        return remote.json.map((x) => String(x).trim()).filter(Boolean);
      }
      return loadFingerprintBlacklist();
    }

    const file =
      type === "ip"
        ? "ip-blacklist.json"
        : type === "provider"
          ? "provider-blacklist.json"
          : "asn-blacklist.json";
    const key =
      type === "ip" ? "ips" : type === "provider" ? "providers" : "asns";
    const remote = await getGithubJsonFile(securityFilePath(file));
    if (remote.ok && remote.json && Array.isArray(remote.json[key])) {
      return remote.json[key].map((x) => String(x).trim()).filter(Boolean);
    }
  } catch {
    // fall through
  }

  if (type === "ip") return loadIpBlacklist();
  if (type === "provider") return loadProviderBlacklist();
  if (type === "asn") return loadAsnBlacklist();
  return loadFingerprintBlacklist();
}

export async function GET(request) {
  try {
    if (!isAdminAuthenticated(request)) {
      return NextResponse.json({ ok: false, error: "unauthorized" }, { status: 401 });
    }

    const [events, ips, providers, asns, fingerprints] = await Promise.all([
      loadEventsForDashboard(),
      loadLiveList("ip"),
      loadLiveList("provider"),
      loadLiveList("asn"),
      loadLiveList("fingerprint")
    ]);

    const blockedEvents = events.filter((e) => e.blocked === true || e.reason);

    return NextResponse.json({
      ok: true,
      githubConfigured: Boolean(getGithubConfig()),
      generatedAt: new Date().toISOString(),
      blacklists: {
        ips,
        providers,
        asns,
        fingerprints
      },
      events: blockedEvents.length ? blockedEvents : events,
      latest: {
        ips: uniqueField(events, "ip"),
        fingerprints: uniqueField(events, "visitorId"),
        providers: uniqueField(events, "provider"),
        asns: uniqueField(events, "asn"),
        countries: uniqueField(events, "country"),
        browsers: uniqueField(events, "browser"),
        devices: uniqueField(events, "device"),
        reasons: uniqueField(events, "reason")
      }
    });
  } catch {
    return NextResponse.json({ ok: false, error: "fail_open" }, { status: 200 });
  }
}

/**
 * @param {object[]} events
 * @param {string} key
 * @returns {string[]}
 */
function uniqueField(events, key) {
  const out = [];
  const seen = new Set();
  for (let i = 0; i < events.length; i++) {
    const v = events[i] && events[i][key];
    if (v == null || v === "") continue;
    const s = String(v);
    if (seen.has(s)) continue;
    seen.add(s);
    out.push(s);
    if (out.length >= 50) break;
  }
  return out;
}
