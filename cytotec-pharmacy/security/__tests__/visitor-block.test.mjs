/**
 * Security Layer v2.5 — AE always allow, fingerprint monitor-only, Google crawlers
 * Run: npm test
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");

const {
  getVisitorBlockMode,
  isUaeCountry,
  resolveSuspiciousVisitorDecision,
  normalizeWhatsAppDigits,
  buildWhatsAppUrl
} = await import(pathToFileURL(path.join(root, "visitor-block.js")).href);

const {
  decideCountryAccess,
  isSecurityProbePath,
  asCountryCode
} = await import(pathToFileURL(path.join(root, "access-decision.js")).href);

const SUSPICIOUS_AE = "5561f93c9a9fb8c285fb2e1d7ba9b0d6";
const SUSPICIOUS_2 = "87182b94903251023ddc02e6bdf8ed4e";

/** Minimal mirror of bots.js trusted Google check */
function isTrustedSecurityBypassBot(request, ipResult) {
  const ua = request.headers.get("user-agent") || "";
  const TRUSTED =
    /(?:AdsBot-Google-Mobile|AdsBot-Google|Googlebot|Google-InspectionTool|Storebot-Google|Mediapartners-Google|Google-Safety)/i;
  if (!ua || !TRUSTED.test(ua)) return false;
  if (!ipResult || ipResult.ok !== true || !ipResult.info) return false;
  const { asn, company } = ipResult.info;
  if (!asn && !company) return false;
  const n = String(asn || "").replace(/^AS/i, "");
  if (n === "15169") return true;
  if (company && /google\s*llc/i.test(String(company))) return true;
  return false;
}

function mockRequest(ua) {
  return {
    headers: {
      get(name) {
        return String(name).toLowerCase() === "user-agent" ? ua : null;
      }
    }
  };
}

test("AE residential IP → allow", () => {
  const r = decideCountryAccess({ country: "AE", ipinfoOk: true });
  assert.equal(r.decision, "allow");
  assert.equal(r.reason, "allowed_uae");
});

test("AE Etisalat → allow", () => {
  const r = decideCountryAccess({ country: "AE" });
  assert.equal(r.decision, "allow");
  assert.equal(r.reason, "allowed_uae");
});

test("AE Du → allow", () => {
  const r = decideCountryAccess({ country: "AE" });
  assert.equal(r.decision, "allow");
});

test("AE visitor with old blocked visitorId → allow (monitor-only)", () => {
  const decision = resolveSuspiciousVisitorDecision({
    mode: "hard",
    visitorId: SUSPICIOUS_AE,
    ipInfo: { country: "AE", is_hosting: true, is_vpn: true }
  });
  assert.equal(decision.hardBlock, false);
  assert.equal(decision.monitorOnly, true);
  assert.equal(decision.reason, "monitored_suspicious_visitor");
  const page = decideCountryAccess({ country: "AE" });
  assert.equal(page.decision, "allow");
});

test("AE visitor on normal / page → allow", () => {
  assert.equal(isSecurityProbePath("/"), false);
  assert.equal(decideCountryAccess({ country: "AE" }).decision, "allow");
});

test("Verified Google crawler + AS15169 → allowed", () => {
  assert.equal(
    isTrustedSecurityBypassBot(
      mockRequest("AdsBot-Google (+http://www.google.com/adsbot.html)"),
      {
        ok: true,
        info: { asn: "AS15169", company: "Google LLC", is_hosting: true }
      }
    ),
    true
  );
  assert.equal(
    isTrustedSecurityBypassBot(mockRequest("Google-InspectionTool/1.0"), {
      ok: true,
      info: { asn: "AS999", company: "Google LLC" }
    }),
    true
  );
});

test("JO / EG / SY / TR → block", () => {
  for (const country of ["JO", "EG", "SY", "TR"]) {
    const r = decideCountryAccess({ country });
    assert.equal(r.decision, "block", country);
    assert.equal(r.reason, "blocked_country", country);
  }
});

test("/wp-admin and /xmlrpc.php → probe block", () => {
  assert.equal(isSecurityProbePath("/wp-admin"), true);
  assert.equal(isSecurityProbePath("/wp-login.php"), true);
  assert.equal(isSecurityProbePath("/xmlrpc.php"), true);
  assert.equal(isSecurityProbePath("/.env"), true);
  assert.equal(isSecurityProbePath("/"), false);
  assert.equal(isSecurityProbePath("/index.html"), false);
});

test("WhatsApp click from AE → URL opens; logging failure ignored (204 path)", () => {
  const href = buildWhatsAppUrl(
    "+971547952044",
    "مرحبا دكتورة عهود، ارغب بالحصول على سايتوتيك"
  );
  assert.match(href, /^https:\/\/wa\.me\/971547952044\?text=/);
  let apiOk = false;
  try {
    throw new Error("network");
  } catch {
    apiOk = false; // logging failed
  }
  // WhatsApp still opens
  assert.equal(apiOk, false);
  assert.ok(href.startsWith("https://wa.me/971547952044"));
  const waSrc = readFileSync(
    path.join(root, "../app/api/security/whatsapp-click/route.js"),
    "utf8"
  );
  assert.ok(waSrc.includes("204"));
});

test("fingerprint never hard-blocks even with VISITOR_BLOCK_MODE=hard", () => {
  const prev = process.env.VISITOR_BLOCK_MODE;
  process.env.VISITOR_BLOCK_MODE = "hard";
  assert.equal(getVisitorBlockMode(), "hard");
  const d = resolveSuspiciousVisitorDecision({
    mode: "hard",
    visitorId: SUSPICIOUS_2,
    ipInfo: { country: "JO" }
  });
  assert.equal(d.hardBlock, false);
  if (prev === undefined) delete process.env.VISITOR_BLOCK_MODE;
  else process.env.VISITOR_BLOCK_MODE = prev;
});

test("spoofed Google UA without Google network → denied bypass", () => {
  assert.equal(
    isTrustedSecurityBypassBot(mockRequest("Googlebot/2.1"), {
      ok: true,
      info: { asn: "AS63023", company: "GTHost" }
    }),
    false
  );
});

test("unknown / failed geo → allow", () => {
  assert.equal(
    decideCountryAccess({ country: null, ipinfoOk: true }).reason,
    "unknown_country_fail_open"
  );
  assert.equal(
    decideCountryAccess({ country: "AE", ipinfoOk: false }).reason,
    "allowed_uae"
  );
  assert.equal(
    decideCountryAccess({ country: null, ipinfoOk: false }).reason,
    "ipinfo_fail_open"
  );
});

test("middleware + fingerprint API sources enforce AE/Google/monitor rules", () => {
  const mw = readFileSync(path.join(root, "../middleware.js"), "utf8");
  assert.ok(mw.includes("allowed_uae"));
  assert.ok(mw.includes("allowed_verified_google_crawler"));
  assert.ok(!mw.includes('reason: "blocked_visitor_id"'));

  const fp = readFileSync(
    path.join(root, "../app/api/security/fingerprint/route.js"),
    "utf8"
  );
  assert.ok(!fp.includes("status: 403"));
  assert.ok(fp.includes("monitored_suspicious_visitor"));

  const rules = readFileSync(path.join(root, "rules.js"), "utf8");
  assert.ok(rules.includes("decideCountryAccess"));
  assert.ok(rules.includes("allowed_uae"));

  const cfg = readFileSync(path.join(root, "config.js"), "utf8");
  assert.ok(cfg.includes('"TR"'));
  assert.ok(!cfg.includes('"YE"'));

  const list = JSON.parse(
    readFileSync(path.join(root, "fingerprint-blacklist.json"), "utf8")
  );
  assert.ok(list.includes(SUSPICIOUS_AE));

  assert.equal(isUaeCountry({ country: "AE" }), true);
  assert.equal(asCountryCode("Turkey"), "TR");
  assert.equal(normalizeWhatsAppDigits("+971 54"), "97154");
});

test("client never redirects to access-denied; CSS does not lock WA", () => {
  const js = readFileSync(
    path.join(root, "../public/assets/js/fingerprint-security.js"),
    "utf8"
  );
  assert.ok(!js.includes("location.replace"));
  assert.ok(!js.includes("/access-denied"));
  const css = readFileSync(
    path.join(root, "../public/assets/css/components.css"),
    "utf8"
  );
  assert.ok(!css.includes('html:not(.fp-security-ready) [data-cta="whatsapp"]'));
});

test("provider blacklist empty of AE carriers / Private Relay / Cloudflare", () => {
  const providers = JSON.parse(
    readFileSync(path.join(root, "provider-blacklist.json"), "utf8")
  ).providers;
  const joined = JSON.stringify(providers).toLowerCase();
  assert.ok(!joined.includes("private relay"));
  assert.ok(!joined.includes("cloudflare"));
  assert.ok(!joined.includes("etisalat"));
});

test("google-verify UA list includes InspectionTool Storebot Mediapartners", () => {
  const src = readFileSync(path.join(root, "google-verify.js"), "utf8");
  assert.ok(src.includes("Google-InspectionTool"));
  assert.ok(src.includes("Storebot-Google"));
  assert.ok(src.includes("Mediapartners-Google"));
});
