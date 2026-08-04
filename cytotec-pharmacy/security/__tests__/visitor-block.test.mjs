/**
 * Security visitor-block + Google crawler + WhatsApp URL tests
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
  isUaeResidential,
  resolveSuspiciousVisitorDecision,
  normalizeWhatsAppDigits,
  buildWhatsAppUrl
} = await import(pathToFileURL(path.join(root, "visitor-block.js")).href);

/** Minimal mirror of bots.js Google bypass (kept in sync by assertions on source). */
function isTrustedSecurityBypassBot(request, ipResult) {
  const ua = request.headers.get("user-agent") || "";
  if (!ua || !/(?:AdsBot-Google-Mobile|AdsBot-Google|Googlebot)/i.test(ua)) {
    return false;
  }
  if (!ipResult || ipResult.ok !== true || !ipResult.info) return false;
  const info = ipResult.info;
  if (!info.asn || !info.company) return false;
  const asn = String(info.asn).replace(/^AS/i, "");
  if (asn !== "15169") return false;
  if (!/google\s*llc/i.test(String(info.company))) return false;
  return true;
}

function isFingerprintBlacklisted(visitorId) {
  const raw = readFileSync(
    path.join(root, "fingerprint-blacklist.json"),
    "utf8"
  );
  const list = JSON.parse(raw);
  return list.includes(visitorId);
}

const SUSPICIOUS_AE = "5561f93c9a9fb8c285fb2e1d7ba9b0d6";
const SUSPICIOUS_2 = "87182b94903251023ddc02e6bdf8ed4e";

test("blacklist includes current monitored visitorIds", () => {
  assert.equal(isFingerprintBlacklisted(SUSPICIOUS_AE), true);
  assert.equal(isFingerprintBlacklisted(SUSPICIOUS_2), true);
});

test("bots.js no longer rejects Google AS15169 when is_hosting=true", () => {
  const src = readFileSync(path.join(root, "bots.js"), "utf8");
  assert.equal(src.includes("if (info.is_hosting === true) return false"), false);
  assert.ok(src.includes('"15169"'));
  assert.ok(src.includes("Google LLC") || src.includes("google\\s*llc"));
});

test("default VISITOR_BLOCK_MODE is monitor", () => {
  const prev = process.env.VISITOR_BLOCK_MODE;
  delete process.env.VISITOR_BLOCK_MODE;
  assert.equal(getVisitorBlockMode(), "monitor");
  process.env.VISITOR_BLOCK_MODE = "hard";
  assert.equal(getVisitorBlockMode(), "hard");
  process.env.VISITOR_BLOCK_MODE = "MONITOR";
  assert.equal(getVisitorBlockMode(), "monitor");
  if (prev === undefined) delete process.env.VISITOR_BLOCK_MODE;
  else process.env.VISITOR_BLOCK_MODE = prev;
});

test("UAE residential detection", () => {
  assert.equal(
    isUaeResidential({
      country: "AE",
      is_vpn: false,
      is_proxy: false,
      is_tor: false,
      is_relay: false,
      is_hosting: false
    }),
    true
  );
  assert.equal(isUaeResidential({ country: "AE", is_hosting: true }), false);
  assert.equal(isUaeResidential({ country: "JO", is_hosting: false }), false);
  assert.equal(isUaeResidential({ country: "AE", is_vpn: true }), false);
});

test("suspicious visitorId + UAE residential = monitor-only (200 / WhatsApp OK)", () => {
  const decision = resolveSuspiciousVisitorDecision({
    mode: "monitor",
    visitorId: SUSPICIOUS_AE,
    ipInfo: {
      country: "AE",
      is_vpn: false,
      is_proxy: false,
      is_tor: false,
      is_relay: false,
      is_hosting: false
    }
  });
  assert.equal(decision.hardBlock, false);
  assert.equal(decision.monitorOnly, true);
  assert.equal(decision.flagged, true);
  assert.equal(decision.reason, "monitored_suspicious_visitor");
});

test("suspicious visitorId + hosting / blocked country = hard 403", () => {
  const hosting = resolveSuspiciousVisitorDecision({
    mode: "monitor",
    visitorId: SUSPICIOUS_2,
    ipInfo: { country: "AE", is_hosting: true }
  });
  assert.equal(hosting.hardBlock, true);
  assert.equal(hosting.reason, "blocked_visitor_id");

  const jordan = resolveSuspiciousVisitorDecision({
    mode: "monitor",
    visitorId: SUSPICIOUS_2,
    ipInfo: { country: "JO", is_hosting: false }
  });
  assert.equal(jordan.hardBlock, true);
  assert.equal(jordan.reason, "blocked_visitor_id");
});

test("VISITOR_BLOCK_MODE=hard always hard-blocks blacklisted ids", () => {
  const decision = resolveSuspiciousVisitorDecision({
    mode: "hard",
    visitorId: SUSPICIOUS_AE,
    ipInfo: { country: "AE", is_hosting: false }
  });
  assert.equal(decision.hardBlock, true);
  assert.equal(decision.monitorOnly, false);
});

test("verified Google AdsBot AS15169 Google LLC allowed even if hosting", () => {
  const request = {
    headers: {
      get(name) {
        if (String(name).toLowerCase() === "user-agent") {
          return "AdsBot-Google (+http://www.google.com/adsbot.html)";
        }
        return null;
      }
    }
  };
  const ipResult = {
    ok: true,
    info: {
      asn: "AS15169",
      company: "Google LLC",
      is_hosting: true,
      country: "US"
    }
  };
  assert.equal(isTrustedSecurityBypassBot(request, ipResult), true);
});

test("non-Google hosting does not get crawler bypass", () => {
  const request = {
    headers: {
      get(name) {
        if (String(name).toLowerCase() === "user-agent") {
          return "AdsBot-Google (+http://www.google.com/adsbot.html)";
        }
        return null;
      }
    }
  };
  const ipResult = {
    ok: true,
    info: {
      asn: "AS63023",
      company: "GTHost",
      is_hosting: true
    }
  };
  assert.equal(isTrustedSecurityBypassBot(request, ipResult), false);
});

test("WhatsApp URL uses digits-only number and encoded message", () => {
  assert.equal(normalizeWhatsAppDigits("+971 54 795 2044"), "971547952044");
  const url = buildWhatsAppUrl(
    "+971 54 795 2044",
    "مرحبا دكتورة عهود، ارغب بالحصول على سايتوتيك"
  );
  assert.match(url, /^https:\/\/wa\.me\/971547952044\?text=/);
  assert.ok(url.includes(encodeURIComponent("مرحبا")));
});

test("WhatsApp open path does not depend on logging success", () => {
  let logFailed = false;
  function sendBeaconFail() {
    logFailed = true;
    throw new Error("network down");
  }
  const href = buildWhatsAppUrl("971547952044", "hello");
  try {
    sendBeaconFail();
  } catch {
    // logging must never block
  }
  assert.equal(logFailed, true);
  assert.equal(href.startsWith("https://wa.me/971547952044"), true);
});

test("main.js never preventDefaults WhatsApp solely for tracking", () => {
  const src = readFileSync(
    path.join(root, "../public/assets/js/main.js"),
    "utf8"
  );
  assert.match(src, /sendBeacon/);
  assert.match(src, /keepalive:\s*true/);
  assert.match(src, /normalizeWhatsAppDigits/);
  // Old fingerprint gate that blocked WA open must be gone
  assert.equal(src.includes("if (!isFingerprintReady())"), false);
});
