/**
 * Security event store for the private admin dashboard
 * ----------------------------------------------------
 * Reads local events.json (bundled / deployed).
 * Appends via GitHub when GITHUB_TOKEN is set (non-blocking callers).
 * Caps at MAX_EVENTS. Never stores secrets.
 */

import localEvents from "./events.json";
import {
  getGithubConfig,
  getGithubJsonFile,
  putGithubFile,
  securityFilePath
} from "./github-files";

export const MAX_EVENTS = 200;
const EVENTS_FILE = "events.json";

/**
 * @param {unknown} raw
 * @returns {object[]}
 */
function normalizeEvents(raw) {
  try {
    if (Array.isArray(raw)) return raw.filter((e) => e && typeof e === "object");
    if (raw && typeof raw === "object" && Array.isArray(raw.events)) {
      return raw.events.filter((e) => e && typeof e === "object");
    }
  } catch {
    // ignore
  }
  return [];
}

/**
 * Local/deployed snapshot (fast — no network).
 * @returns {object[]}
 */
export function getLocalEvents() {
  return normalizeEvents(localEvents).slice(0, MAX_EVENTS);
}

/**
 * @param {object} event
 * @returns {object}
 */
export function sanitizeEvent(event) {
  const e = event && typeof event === "object" ? event : {};
  return {
    timestamp: e.timestamp || new Date().toISOString(),
    ip: e.ip || null,
    visitorId: e.visitorId || null,
    provider: e.provider || null,
    company: e.company || null,
    asn: e.asn || null,
    country: e.country || null,
    reason: e.reason || null,
    blocked: e.blocked === true,
    userAgent: e.userAgent ? String(e.userAgent).slice(0, 300) : null,
    platform: e.platform || null,
    language: e.language || null,
    timezone: e.timezone || null,
    screen: e.screen || null,
    touchSupport: e.touchSupport === true,
    hardwareConcurrency: e.hardwareConcurrency ?? null,
    deviceMemory: e.deviceMemory ?? null,
    browser: e.browser || null,
    device: e.device || null,
    pathname: e.pathname || null,
    gclid: e.gclid || null,
    gbraid: e.gbraid || null,
    wbraid: e.wbraid || null
  };
}

/**
 * Infer browser label from UA (lightweight).
 * @param {string|null|undefined} ua
 * @returns {string|null}
 */
export function inferBrowser(ua) {
  if (!ua) return null;
  const s = String(ua);
  if (/Edg\//i.test(s)) return "Edge";
  if (/OPR\/|Opera/i.test(s)) return "Opera";
  if (/Chrome\//i.test(s) && !/Edg\//i.test(s)) return "Chrome";
  if (/Safari\//i.test(s) && !/Chrome\//i.test(s)) return "Safari";
  if (/Firefox\//i.test(s)) return "Firefox";
  if (/SamsungBrowser/i.test(s)) return "Samsung Internet";
  return "Other";
}

/**
 * Infer device label.
 * @param {{ userAgent?: string|null, platform?: string|null, touchSupport?: boolean }} e
 * @returns {string|null}
 */
export function inferDevice(e) {
  const ua = e.userAgent || "";
  if (/iPhone/i.test(ua)) return "iPhone";
  if (/iPad/i.test(ua)) return "iPad";
  if (/Android/i.test(ua) && /Mobile/i.test(ua)) return "Android Phone";
  if (/Android/i.test(ua)) return "Android Tablet";
  if (/Mac OS X/i.test(ua) && !/iPhone|iPad/i.test(ua)) return "Mac";
  if (/Windows/i.test(ua)) return "Windows";
  if (/Linux/i.test(ua)) return "Linux";
  if (e.touchSupport) return "Touch Device";
  return e.platform || null;
}

/**
 * Append one event to GitHub events.json (awaitable). Safe to fire-and-forget.
 * @param {object} event
 * @returns {Promise<{ ok: boolean, error?: string }>}
 */
export async function appendSecurityEvent(event) {
  if (!getGithubConfig()) {
    return { ok: false, error: "github_not_configured" };
  }

  try {
    const path = securityFilePath(EVENTS_FILE);
    const current = await getGithubJsonFile(path);
    const existing = current.ok ? normalizeEvents(current.json) : getLocalEvents();

    const nextEvent = sanitizeEvent({
      ...event,
      browser: event.browser || inferBrowser(event.userAgent),
      device: event.device || inferDevice(event)
    });

    const next = [nextEvent, ...existing].slice(0, MAX_EVENTS);
    const content = `${JSON.stringify({ events: next }, null, 2)}\n`;

    if (!current.ok) {
      // File may not exist yet — cannot create without sha on some APIs;
      // try put without sha for create
      const cfg = getGithubConfig();
      if (!cfg) return { ok: false, error: "github_not_configured" };
      const url = `https://api.github.com/repos/${cfg.repo}/contents/${path}`;
      const res = await fetch(url, {
        method: "PUT",
        headers: {
          authorization: `Bearer ${cfg.token}`,
          accept: "application/vnd.github+json",
          "x-github-api-version": "2022-11-28",
          "content-type": "application/json",
          "user-agent": "dr-ohood-security-admin"
        },
        body: JSON.stringify({
          message: "security: append event log",
          content: Buffer.from(content, "utf8").toString("base64"),
          branch: cfg.branch
        })
      });
      return res.ok ? { ok: true } : { ok: false, error: `github_put_${res.status}` };
    }

    const put = await putGithubFile({
      path,
      content,
      sha: current.sha,
      message: "security: append event log"
    });
    return put.ok ? { ok: true } : { ok: false, error: put.error };
  } catch (error) {
    return {
      ok: false,
      error: error && error.message ? error.message : "append_failed"
    };
  }
}

/**
 * Prefer live GitHub events when configured; else local snapshot.
 * @returns {Promise<object[]>}
 */
export async function loadEventsForDashboard() {
  if (getGithubConfig()) {
    const remote = await getGithubJsonFile(securityFilePath(EVENTS_FILE));
    if (remote.ok) return normalizeEvents(remote.json).slice(0, MAX_EVENTS);
  }
  return getLocalEvents();
}
