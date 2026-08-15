/**
 * Landing lead form — name / phone / emirate → /api/leads → /thank-you
 * Vanilla JS only (static HTML landing). No React hydration.
 */
(function () {
  "use strict";

  var form = document.getElementById("lead-form");
  if (!form) return;

  function getAdsIds() {
    try {
      if (window.AdsIdentity && typeof window.AdsIdentity.getAll === "function") {
        return window.AdsIdentity.getAll();
      }
    } catch (e) {}
    return { gclid: null, gbraid: null, wbraid: null };
  }

  function setError(field, message) {
    var el = form.querySelector('[data-error-for="' + field + '"]');
    if (!el) return;
    if (message) {
      el.textContent = message;
      el.hidden = false;
    } else {
      el.textContent = "";
      el.hidden = true;
    }
  }

  function clearErrors() {
    ["nom", "telephone", "emirate", "form"].forEach(function (f) {
      setError(f, "");
    });
  }

  function validate() {
    clearErrors();
    var nom = (form.nom.value || "").trim();
    var telephone = (form.telephone.value || "").trim();
    var emirate = (form.emirate.value || "").trim();
    var ok = true;

    if (nom.length < 2) {
      setError("nom", "يرجى إدخال الاسم.");
      ok = false;
    }
    if (telephone.replace(/\D/g, "").length < 8) {
      setError("telephone", "يرجى إدخال رقم هاتف صحيح.");
      ok = false;
    }
    if (!emirate) {
      setError("emirate", "يرجى اختيار الإمارة.");
      ok = false;
    }
    return ok;
  }

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    if (form.getAttribute("data-submitting") === "1") return;
    if (!validate()) return;

    var btn = form.querySelector('button[type="submit"]');
    var ids = getAdsIds();
    var payload = {
      nom: (form.nom.value || "").trim(),
      telephone: (form.telephone.value || "").trim(),
      emirate: (form.emirate.value || "").trim(),
      gclid: ids.gclid || null,
      gbraid: ids.gbraid || null,
      wbraid: ids.wbraid || null
    };

    form.setAttribute("data-submitting", "1");
    if (btn) {
      btn.disabled = true;
      btn.textContent = "جاري الإرسال…";
    }

    fetch("/api/leads", {
      method: "POST",
      headers: { "content-type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(payload),
      keepalive: true
    })
      .then(function (res) {
        return res.json().catch(function () {
          return { ok: false };
        });
      })
      .then(function (data) {
        if (data && data.ok) {
          try {
            if (typeof gtag === "function") {
              gtag("event", "generate_lead", {
                event_category: "lead_form",
                event_label: payload.emirate
              });
            }
          } catch (e) {}
          window.location.assign("/thank-you");
          return;
        }
        setError(
          "form",
          (data && data.error) || "تعذّر الإرسال. حاولي مرة أخرى."
        );
        form.setAttribute("data-submitting", "0");
        if (btn) {
          btn.disabled = false;
          btn.textContent = "إرسال الطلب";
        }
      })
      .catch(function () {
        setError("form", "تعذّر الإرسال. تحقّقي من الاتصال وحاولي مرة أخرى.");
        form.setAttribute("data-submitting", "0");
        if (btn) {
          btn.disabled = false;
          btn.textContent = "إرسال الطلب";
        }
      });
  });
})();
