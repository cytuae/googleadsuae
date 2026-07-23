"use client";

/**
 * Optional React client collector (App Router).
 * The production landing is static HTML — primary collector is:
 *   public/assets/js/fingerprint-security.js
 * This component covers any React-rendered routes that mount it.
 *
 * Reuses the same AdsIdentity storage keys as the static landing scripts.
 */

import { useEffect } from "react";

const SESSION_KEY = "fp_security_sent_v1";
const LS = {
  gclid: "ads_gclid_v1",
  gbraid: "ads_gbraid_v1",
  wbraid: "ads_wbraid_v1",
  visitorId: "fp_visitor_id_v1"
};

function queryParam(name) {
  try {
    return new URLSearchParams(window.location.search).get(name);
  } catch {
    return null;
  }
}

function storageSet(key, value) {
  if (!value) return;
  const v = String(value).slice(0, 256);
  try {
    sessionStorage.setItem(key, v);
  } catch {
    // ignore
  }
  try {
    localStorage.setItem(key, v);
  } catch {
    // ignore
  }
}

function storageGet(key) {
  try {
    const s = sessionStorage.getItem(key);
    if (s) return s;
  } catch {
    // ignore
  }
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function persistClickIdsFromUrl() {
  ["gclid", "gbraid", "wbraid"].forEach((name) => {
    const v = queryParam(name);
    if (v) storageSet(LS[name], v);
  });
}

function getClickId(name) {
  const fromUrl = queryParam(name);
  if (fromUrl) {
    storageSet(LS[name], fromUrl);
    return String(fromUrl).slice(0, 256);
  }
  return storageGet(LS[name]);
}

function collectDevice() {
  const nav = navigator || {};
  const scr = window.screen || {};
  let timezone = "";
  try {
    timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || "";
  } catch {
    timezone = "";
  }

  return {
    userAgent: nav.userAgent || "",
    platform: nav.platform || "",
    language: nav.language || (nav.languages && nav.languages[0]) || "",
    timezone,
    screenWidth: scr.width || 0,
    screenHeight: scr.height || 0,
    devicePixelRatio: window.devicePixelRatio || 1,
    touchSupport:
      "ontouchstart" in window ||
      (typeof nav.maxTouchPoints === "number" && nav.maxTouchPoints > 0),
    hardwareConcurrency:
      typeof nav.hardwareConcurrency === "number" ? nav.hardwareConcurrency : 0,
    deviceMemory: typeof nav.deviceMemory === "number" ? nav.deviceMemory : null,
    pathname: window.location.pathname || "/",
    gclid: getClickId("gclid"),
    gbraid: getClickId("gbraid"),
    wbraid: getClickId("wbraid"),
    utm_source: queryParam("utm_source"),
    utm_medium: queryParam("utm_medium"),
    utm_campaign: queryParam("utm_campaign"),
    utm_term: queryParam("utm_term"),
    utm_content: queryParam("utm_content")
  };
}

export default function FingerprintCollector() {
  useEffect(() => {
    let cancelled = false;
    persistClickIdsFromUrl();

    async function run() {
      try {
        if (sessionStorage.getItem(SESSION_KEY) === "1") return;
      } catch {
        // ignore
      }

      try {
        const FingerprintJS = (await import("@fingerprintjs/fingerprintjs"))
          .default;
        const agent = await FingerprintJS.load();
        const result = await agent.get();
        if (cancelled || !result?.visitorId) return;

        storageSet(LS.visitorId, result.visitorId);

        const payload = { ...collectDevice(), visitorId: result.visitorId };
        const res = await fetch("/api/security/fingerprint", {
          method: "POST",
          headers: { "content-type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify(payload),
          keepalive: true
        });

        try {
          sessionStorage.setItem(SESSION_KEY, "1");
        } catch {
          // ignore
        }

        if (res.status === 403) {
          window.location.replace("/access-denied");
        }
      } catch {
        // Fail-safe: never break the page
      }
    }

    void run();
    return () => {
      cancelled = true;
    };
  }, []);

  return null;
}
