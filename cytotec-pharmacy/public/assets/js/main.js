(function () {
  "use strict";

  /* ===== SITE CONFIG — عدّلي هذه القيم قبل النشر ===== */
  var SITE = window.SITE_CONFIG || {
    whatsapp: "971547952044",
    domain: "https://dr-ohood.clinic",
    hours: "الرد خلال دقايق",
    waDefaultText: "مرحبا دكتورة عهود، ارغب بالحصول على سايتوتيك"
  };

  /** Digits-only international number (no + / spaces). */
  function normalizeWhatsAppDigits(raw) {
    return String(raw || "").replace(/\D/g, "");
  }

  SITE.whatsapp = normalizeWhatsAppDigits(SITE.whatsapp) || "971547952044";

  function waUrl(text) {
    var phone = normalizeWhatsAppDigits(SITE.whatsapp) || "971547952044";
    var msg = encodeURIComponent(text || SITE.waDefaultText || "");
    return "https://wa.me/" + phone + "?text=" + msg;
  }

  function newEventId() {
    try {
      if (window.crypto && typeof crypto.randomUUID === "function") {
        return crypto.randomUUID();
      }
    } catch (e) {}
    return "wa_" + Date.now() + "_" + Math.random().toString(36).slice(2, 10);
  }

  function getTimezone() {
    try {
      return Intl.DateTimeFormat().resolvedOptions().timeZone || "";
    } catch (e) {
      return "";
    }
  }

  function getScreen() {
    var scr = window.screen || {};
    var w = scr.width || 0;
    var h = scr.height || 0;
    return w && h ? w + "x" + h : "";
  }

  function inferDeviceLabel() {
    var ua = navigator.userAgent || "";
    if (/iPhone/i.test(ua)) return "iPhone";
    if (/iPad/i.test(ua)) return "iPad";
    if (/Android/i.test(ua) && /Mobile/i.test(ua)) return "Android Phone";
    if (/Android/i.test(ua)) return "Android Tablet";
    if (/Mac OS X/i.test(ua) && !/iPhone|iPad/i.test(ua)) return "Mac";
    if (/Windows/i.test(ua)) return "Windows";
    if (/Linux/i.test(ua)) return "Linux";
    return navigator.platform || "";
  }

  function inferBrowserLabel() {
    var ua = navigator.userAgent || "";
    if (/Edg\//i.test(ua)) return "Edge";
    if (/OPR\/|Opera/i.test(ua)) return "Opera";
    if (/Chrome\//i.test(ua) && !/Edg\//i.test(ua)) return "Chrome";
    if (/Safari\//i.test(ua) && !/Chrome\//i.test(ua)) return "Safari";
    if (/Firefox\//i.test(ua)) return "Firefox";
    return "";
  }

  function getIdentity() {
    if (window.AdsIdentity && typeof window.AdsIdentity.getAll === "function") {
      return window.AdsIdentity.getAll();
    }
    return { gclid: null, gbraid: null, wbraid: null, visitorId: null };
  }

  /**
   * Fire-and-forget beacon (never blocks WhatsApp navigation).
   * @param {Object} payload
   */
  function sendWhatsAppBeacon(payload) {
    var url = "/api/security/whatsapp-click";
    var body = JSON.stringify(payload);
    try {
      if (navigator.sendBeacon) {
        var blob = new Blob([body], { type: "application/json" });
        if (navigator.sendBeacon(url, blob)) return;
      }
    } catch (e) {}
    try {
      fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: body,
        keepalive: true,
        credentials: "same-origin"
      }).catch(function () {});
    } catch (e2) {}
  }

  /** Google Ads WhatsApp conversion — click only; dedupe rapid double-fires. */
  var ADS_WA_CONVERSION_SEND_TO = "AW-17219982138/E77WCKvEh-cEELqnKNA";
  var lastAdsWaConversionAt = 0;
  var ADS_WA_CONVERSION_DEDUP_MS = 2000;

  function fireGoogleAdsWhatsAppConversion() {
    var now = Date.now();
    if (now - lastAdsWaConversionAt < ADS_WA_CONVERSION_DEDUP_MS) return;
    lastAdsWaConversionAt = now;
    try {
      if (typeof gtag !== "function") return;
      gtag("event", "conversion", {
        send_to: ADS_WA_CONVERSION_SEND_TO,
        value: 1.0,
        currency: "MAD"
      });
    } catch (e) {}
  }

  /**
   * Central WhatsApp click tracker — one event per real click.
   * Does not await; must never delay opening WhatsApp.
   * @param {string} buttonLocation
   */
  function trackWhatsAppClick(buttonLocation) {
    var location = buttonLocation || "whatsapp";
    var ids = getIdentity();
    var pathname = window.location.pathname || "/";
    var eventId = newEventId();
    var timestamp = new Date().toISOString();

    var payload = {
      event: "WHATSAPP_CLICK",
      timestamp: timestamp,
      eventId: eventId,
      visitorId: ids.visitorId || null,
      gclid: ids.gclid || null,
      gbraid: ids.gbraid || null,
      wbraid: ids.wbraid || null,
      pathname: pathname,
      buttonLocation: location,
      referrer: document.referrer || "",
      timezone: getTimezone(),
      screen: getScreen(),
      device: inferDeviceLabel(),
      browser: inferBrowserLabel(),
      userAgent: navigator.userAgent || "",
      platform: navigator.platform || "",
      touchSupport:
        "ontouchstart" in window ||
        (typeof navigator.maxTouchPoints === "number" &&
          navigator.maxTouchPoints > 0)
    };

    sendWhatsAppBeacon(payload);

    // Google Ads conversion — only on real WhatsApp click (not page load)
    fireGoogleAdsWhatsAppConversion();

    try {
      if (typeof gtag === "function") {
        gtag("event", "whatsapp_click", {
          button_location: location,
          page_path: pathname
        });
      }
    } catch (e) {}

    try {
      if (typeof fbq === "function") {
        fbq("trackCustom", "WhatsAppClick", { source: location });
      }
    } catch (e2) {}

    try {
      window.dataLayer = window.dataLayer || [];
      window.dataLayer.push({
        event: "whatsapp_click",
        cta_source: location,
        button_location: location,
        page_path: pathname,
        eventId: eventId
      });
    } catch (e3) {}
  }

  // Expose for any future CTAs
  window.trackWhatsAppClick = trackWhatsAppClick;

  // Apply domain to canonical / OG if still placeholder-relative
  var canonical = document.querySelector('link[rel="canonical"]');
  if (canonical && SITE.domain) {
    canonical.setAttribute("href", SITE.domain.replace(/\/$/, "") + "/");
  }
  var ogUrl = document.querySelector('meta[property="og:url"]');
  if (ogUrl && SITE.domain) {
    ogUrl.setAttribute("content", SITE.domain.replace(/\/$/, "") + "/");
  }
  var ogImage = document.querySelector('meta[property="og:image"]');
  if (ogImage && SITE.domain) {
    var imgPath = ogImage.getAttribute("content") || "";
    if (imgPath && imgPath.indexOf("http") !== 0) {
      ogImage.setAttribute(
        "content",
        SITE.domain.replace(/\/$/, "") + "/" + imgPath.replace(/^\//, "")
      );
    }
  }

  // Wire all WhatsApp CTAs — same message everywhere; one listener each.
  // Tracking never blocks navigation. href is always a valid wa.me link.
  document.querySelectorAll("[data-cta='whatsapp']").forEach(function (el) {
    if (el.getAttribute("data-wa-tracked") === "1") return;
    el.setAttribute("data-wa-tracked", "1");
    el.removeAttribute("data-wa-text");
    var href = waUrl(SITE.waDefaultText);
    el.setAttribute("href", href);
    el.setAttribute("target", "_blank");
    el.setAttribute("rel", "noopener noreferrer");
    el.addEventListener("click", function (event) {
      // Refresh href in case SITE_CONFIG loaded late; never block open.
      var openHref = waUrl(SITE.waDefaultText);
      el.setAttribute("href", openHref);
      try {
        trackWhatsAppClick(el.getAttribute("data-cta-source") || "whatsapp");
      } catch (e) {}
      // Only preventDefault when we immediately open the same link ourselves
      // (fallback if browser would otherwise keep a stale # href).
      if (!openHref || openHref.indexOf("https://wa.me/") !== 0) {
        return;
      }
      if ((el.getAttribute("href") || "") === "#" || !el.getAttribute("href")) {
        event.preventDefault();
        window.open(openHref, "_blank", "noopener,noreferrer");
      }
    });
  });

  // Any other WhatsApp links (wa.me / api.whatsapp.com) not marked data-cta
  document
    .querySelectorAll("a[href*='wa.me'], a[href*='api.whatsapp.com']")
    .forEach(function (el) {
      if (el.getAttribute("data-wa-tracked") === "1") return;
      el.setAttribute("data-wa-tracked", "1");
      el.addEventListener("click", function () {
        try {
          trackWhatsAppClick(
            el.getAttribute("data-cta-source") || "whatsapp_link"
          );
        } catch (e) {}
      });
    });

  // Footer dynamic bits
  var yearEl = document.getElementById("year");
  if (yearEl) yearEl.textContent = String(new Date().getFullYear());

  var hoursEl = document.querySelector("[data-site-hours]");
  if (hoursEl && SITE.hours) hoursEl.textContent = SITE.hours;

  var header = document.querySelector("[data-header]");
  if (header) {
    var onScroll = function () {
      header.classList.toggle("is-scrolled", window.scrollY > 24);
    };
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
  }

  document.querySelectorAll("[data-faq-item]").forEach(function (item) {
    var btn = item.querySelector("[data-faq-btn]");
    if (!btn) return;

    btn.addEventListener("click", function () {
      var open = item.classList.contains("is-open");
      document.querySelectorAll("[data-faq-item].is-open").forEach(function (el) {
        el.classList.remove("is-open");
        var b = el.querySelector("[data-faq-btn]");
        if (b) b.setAttribute("aria-expanded", "false");
      });
      if (!open) {
        item.classList.add("is-open");
        btn.setAttribute("aria-expanded", "true");
      }
    });
  });

  var reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var reveals = document.querySelectorAll(".reveal");

  if (reduceMotion || !("IntersectionObserver" in window)) {
    reveals.forEach(function (el) {
      el.classList.add("is-visible");
    });
  } else {
    var io = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-visible");
            io.unobserve(entry.target);
          }
        });
      },
      { rootMargin: "0px 0px -8% 0px", threshold: 0.12 }
    );
    reveals.forEach(function (el) {
      io.observe(el);
    });
  }
})();
