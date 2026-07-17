(function () {
  "use strict";

  /* ===== SITE CONFIG — عدّلي هذه القيم قبل النشر ===== */
  var SITE = window.SITE_CONFIG || {
    whatsapp: "971547952044",
    domain: "https://dr-ohood.clinic",
    hours: "الرد خلال دقايق",
    waDefaultText: "مرحبا دكتورة عهود، أرغب باستشارة مجانية"
  };

  function waUrl(text) {
    var msg = encodeURIComponent(text || SITE.waDefaultText);
    return "https://wa.me/" + SITE.whatsapp + "?text=" + msg;
  }

  function trackWhatsApp(source) {
    try {
      if (typeof gtag === "function") {
        gtag("event", "whatsapp_click", {
          event_category: "conversion",
          event_label: source || "whatsapp"
        });
      }
      if (typeof fbq === "function") {
        fbq("trackCustom", "WhatsAppClick", { source: source || "whatsapp" });
      }
      window.dataLayer = window.dataLayer || [];
      window.dataLayer.push({
        event: "whatsapp_click",
        cta_source: source || "whatsapp"
      });
    } catch (e) {}
  }

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

  // Wire all WhatsApp CTAs from one config
  document.querySelectorAll("[data-cta='whatsapp']").forEach(function (el) {
    var custom = el.getAttribute("data-wa-text");
    el.setAttribute("href", waUrl(custom || SITE.waDefaultText));
    el.setAttribute("target", "_blank");
    el.setAttribute("rel", "noopener noreferrer");
    el.addEventListener("click", function () {
      trackWhatsApp(el.getAttribute("data-cta-source") || "whatsapp");
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
