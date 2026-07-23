/**
 * Ads click-id + visitorId persistence (shared)
 * ---------------------------------------------
 * Captures gclid / gbraid / wbraid from the URL once and keeps them in
 * localStorage + sessionStorage across in-site navigation.
 * Stores FingerprintJS visitorId for WhatsApp click enrichment.
 * Never stores medical text, chat content, or phone numbers.
 */
(function (window) {
  "use strict";

  var LS = {
    gclid: "ads_gclid_v1",
    gbraid: "ads_gbraid_v1",
    wbraid: "ads_wbraid_v1",
    visitorId: "fp_visitor_id_v1"
  };

  /**
   * @param {string} key
   * @returns {string|null}
   */
  function storageGet(key) {
    try {
      if (window.sessionStorage) {
        var s = sessionStorage.getItem(key);
        if (s) return s;
      }
    } catch (e) {}
    try {
      if (window.localStorage) {
        var l = localStorage.getItem(key);
        if (l) return l;
      }
    } catch (e2) {}
    return null;
  }

  /**
   * @param {string} key
   * @param {string} value
   */
  function storageSet(key, value) {
    if (!value) return;
    var v = String(value).slice(0, 256);
    try {
      if (window.sessionStorage) sessionStorage.setItem(key, v);
    } catch (e) {}
    try {
      if (window.localStorage) localStorage.setItem(key, v);
    } catch (e2) {}
  }

  /**
   * @param {string} name
   * @returns {string|null}
   */
  function queryParam(name) {
    try {
      return new URLSearchParams(window.location.search).get(name);
    } catch (e) {
      return null;
    }
  }

  /**
   * Prefer fresh URL params; otherwise return stored value.
   * @param {"gclid"|"gbraid"|"wbraid"} name
   * @returns {string|null}
   */
  function getClickId(name) {
    var fromUrl = queryParam(name);
    if (fromUrl) {
      storageSet(LS[name], fromUrl);
      return String(fromUrl).slice(0, 256);
    }
    return storageGet(LS[name]);
  }

  function captureFromUrl() {
    ["gclid", "gbraid", "wbraid"].forEach(function (name) {
      var v = queryParam(name);
      if (v) storageSet(LS[name], v);
    });
  }

  /**
   * @param {string} visitorId
   */
  function setVisitorId(visitorId) {
    if (!visitorId) return;
    storageSet(LS.visitorId, String(visitorId).slice(0, 128));
  }

  /**
   * @returns {string|null}
   */
  function getVisitorId() {
    return storageGet(LS.visitorId);
  }

  /**
   * @returns {{ gclid: string|null, gbraid: string|null, wbraid: string|null, visitorId: string|null }}
   */
  function getAll() {
    return {
      gclid: getClickId("gclid"),
      gbraid: getClickId("gbraid"),
      wbraid: getClickId("wbraid"),
      visitorId: getVisitorId()
    };
  }

  captureFromUrl();

  window.AdsIdentity = {
    captureFromUrl: captureFromUrl,
    getClickId: getClickId,
    getAll: getAll,
    getVisitorId: getVisitorId,
    setVisitorId: setVisitorId
  };
})(window);
