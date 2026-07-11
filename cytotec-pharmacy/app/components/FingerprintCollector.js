"use client";

/**
 * Optional React client collector (App Router).
 * The production landing is static HTML — primary collector is:
 *   public/assets/js/fingerprint-security.js
 * This component covers any React-rendered routes that mount it.
 */

import { useEffect } from "react";

const SESSION_KEY = "fp_security_sent_v1";

function queryParam(name) {
  try {
    return new URLSearchParams(window.location.search).get(name);
  } catch {
    return null;
  }
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
    gclid: queryParam("gclid"),
    gbraid: queryParam("gbraid"),
    wbraid: queryParam("wbraid"),
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
