/**
 * Device Fingerprint Security — client service (v1)
 * -------------------------------------------------
 * Runs once per page session (sessionStorage guard).
 * Uses @fingerprintjs/fingerprintjs (vendored UMD) to generate visitorId,
 * then POSTs device + Ads identifiers to /api/security/fingerprint.
 * On 403 → redirect to /access-denied. Errors never break the page.
 *
 * Reuses window.AdsIdentity for gclid/gbraid/wbraid + visitorId persistence.
 */
(function () {
  "use strict";

  var SESSION_KEY = "fp_security_sent_v1";

  // Always refresh click-ids from URL (even if fingerprint already sent)
  try {
    if (window.AdsIdentity && typeof window.AdsIdentity.captureFromUrl === "function") {
      window.AdsIdentity.captureFromUrl();
    }
  } catch (e) {}

  try {
    if (window.sessionStorage && sessionStorage.getItem(SESSION_KEY) === "1") {
      return;
    }
  } catch (e) {
    // ignore storage errors
  }

  function queryParam(name) {
    try {
      return new URLSearchParams(window.location.search).get(name);
    } catch (e) {
      return null;
    }
  }

  function adsId(name) {
    try {
      if (window.AdsIdentity && typeof window.AdsIdentity.getClickId === "function") {
        return window.AdsIdentity.getClickId(name);
      }
    } catch (e) {}
    return queryParam(name);
  }

  function collectDevice() {
    var nav = navigator || {};
    var scr = window.screen || {};
    var timezone = "";
    try {
      timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || "";
    } catch (e) {
      timezone = "";
    }

    return {
      userAgent: nav.userAgent || "",
      platform: nav.platform || "",
      language: nav.language || (nav.languages && nav.languages[0]) || "",
      timezone: timezone,
      screenWidth: scr.width || 0,
      screenHeight: scr.height || 0,
      devicePixelRatio: window.devicePixelRatio || 1,
      touchSupport:
        "ontouchstart" in window ||
        (typeof nav.maxTouchPoints === "number" && nav.maxTouchPoints > 0),
      hardwareConcurrency:
        typeof nav.hardwareConcurrency === "number"
          ? nav.hardwareConcurrency
          : 0,
      deviceMemory:
        typeof nav.deviceMemory === "number" ? nav.deviceMemory : null,
      pathname: window.location.pathname || "/",
      gclid: adsId("gclid"),
      gbraid: adsId("gbraid"),
      wbraid: adsId("wbraid"),
      utm_source: queryParam("utm_source"),
      utm_medium: queryParam("utm_medium"),
      utm_campaign: queryParam("utm_campaign"),
      utm_term: queryParam("utm_term"),
      utm_content: queryParam("utm_content")
    };
  }

  function markSent() {
    try {
      if (window.sessionStorage) {
        sessionStorage.setItem(SESSION_KEY, "1");
      }
    } catch (e) {
      // ignore
    }
  }

  function postFingerprint(visitorId) {
    try {
      if (window.AdsIdentity && typeof window.AdsIdentity.setVisitorId === "function") {
        window.AdsIdentity.setVisitorId(visitorId);
      }
    } catch (e) {}

    var payload = collectDevice();
    payload.visitorId = visitorId;

    return fetch("/api/security/fingerprint", {
      method: "POST",
      headers: { "content-type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(payload),
      keepalive: true
    })
      .then(function (res) {
        markSent();
        if (res && res.status === 403) {
          window.location.replace("/access-denied");
        }
      })
      .catch(function () {
        // Fail-safe: never break landing / tracking
      });
  }

  function start(FingerprintJS) {
    if (!FingerprintJS || typeof FingerprintJS.load !== "function") {
      return;
    }

    FingerprintJS.load()
      .then(function (agent) {
        return agent.get();
      })
      .then(function (result) {
        if (!result || !result.visitorId) return;
        return postFingerprint(String(result.visitorId));
      })
      .catch(function () {
        // Fail-safe
      });
  }

  if (window.FingerprintJS) {
    start(window.FingerprintJS);
  }
})();
