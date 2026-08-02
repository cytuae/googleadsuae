/**
 * Hard IP denylist — thin wrapper over Security Layer v2 JSON
 * -----------------------------------------------------------
 * Source of truth: security/ip-blacklist.json
 * Add future IPs there (not in this file).
 */

import {
  loadIpBlacklist,
  isIpBlacklisted,
  isIpRangeBlacklisted
} from "./blacklists";

/** @type {readonly string[]} */
export const BLOCKED_IPS = Object.freeze(loadIpBlacklist());

/** @type {ReadonlySet<string>} */
export const BLOCKED_IP_SET = new Set(BLOCKED_IPS);

/**
 * Exact IP denylist.
 * @param {string|null|undefined} ip
 * @returns {boolean}
 */
export function isBlockedIP(ip) {
  return isIpBlacklisted(ip);
}

/**
 * CIDR / prefix denylist (blocked_ip_range).
 * @param {string|null|undefined} ip
 * @returns {boolean}
 */
export function isBlockedIPRange(ip) {
  return isIpRangeBlacklisted(ip);
}
