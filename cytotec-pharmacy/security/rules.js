/**
 * Security rules engine (scaffold)
 * --------------------------------
 * Future: combine provider results into allow / challenge / block decisions.
 * Today: always allow so the pipeline can be wired safely in production.
 */

/**
 * @typedef {'allow' | 'challenge' | 'block'} RuleDecision
 *
 * @typedef {Object} RulesResult
 * @property {RuleDecision} decision
 * @property {boolean} allow
 * @property {string[]} matchedRules
 * @property {string} [reason]
 */

/**
 * Apply security rules to aggregated provider results.
 *
 * @param {{
 *   request: Request,
 *   config?: Object,
 *   ipResult?: Object,
 *   fingerprintResult?: Object
 * }} context
 * @returns {Promise<RulesResult>}
 */
export async function applyRules(context) {
  void context;

  // STAGE: rules — no blocking policies active yet
  return {
    decision: "allow",
    allow: true,
    matchedRules: [],
    reason: "default_allow_scaffold"
  };
}
