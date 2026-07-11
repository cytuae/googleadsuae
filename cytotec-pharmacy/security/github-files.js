/**
 * GitHub Contents API — durable updates for blacklist / events JSON
 * -----------------------------------------------------------------
 * Used by the private admin dashboard so Block buttons update:
 *   security/ip-blacklist.json
 *   security/provider-blacklist.json
 *   security/asn-blacklist.json
 *   security/fingerprint-blacklist.json
 * without manual editing. Requires GITHUB_TOKEN (contents:write).
 *
 * Never logs the token.
 */

const DEFAULT_REPO = "cytuae/googleadsuae";
const DEFAULT_BRANCH = "main";
const BASE_PATH = "cytotec-pharmacy/security";

/**
 * @returns {{ token: string, repo: string, branch: string } | null}
 */
export function getGithubConfig() {
  const token = String(process.env.GITHUB_TOKEN || "").trim();
  if (!token) return null;
  return {
    token,
    repo: String(process.env.GITHUB_REPO || DEFAULT_REPO).trim() || DEFAULT_REPO,
    branch:
      String(process.env.GITHUB_BRANCH || DEFAULT_BRANCH).trim() || DEFAULT_BRANCH
  };
}

/**
 * @param {string} filename
 * @returns {string}
 */
export function securityFilePath(filename) {
  return `${BASE_PATH}/${filename}`;
}

/**
 * @param {string} path
 * @returns {Promise<{ ok: true, sha: string, json: any, raw: string } | { ok: false, error: string }>}
 */
export async function getGithubJsonFile(path) {
  const cfg = getGithubConfig();
  if (!cfg) return { ok: false, error: "github_not_configured" };

  try {
    const url = `https://api.github.com/repos/${cfg.repo}/contents/${path}?ref=${encodeURIComponent(cfg.branch)}`;
    const res = await fetch(url, {
      headers: {
        authorization: `Bearer ${cfg.token}`,
        accept: "application/vnd.github+json",
        "x-github-api-version": "2022-11-28",
        "user-agent": "dr-ohood-security-admin"
      },
      cache: "no-store"
    });

    if (!res.ok) {
      return { ok: false, error: `github_get_${res.status}` };
    }

    const data = await res.json();
    const raw = Buffer.from(data.content.replace(/\n/g, ""), "base64").toString(
      "utf8"
    );
    return {
      ok: true,
      sha: data.sha,
      raw,
      json: JSON.parse(raw)
    };
  } catch (error) {
    return {
      ok: false,
      error: error && error.message ? error.message : "github_get_failed"
    };
  }
}

/**
 * @param {{
 *   path: string,
 *   content: string,
 *   sha: string,
 *   message: string
 * }} opts
 * @returns {Promise<{ ok: true } | { ok: false, error: string }>}
 */
export async function putGithubFile(opts) {
  const cfg = getGithubConfig();
  if (!cfg) return { ok: false, error: "github_not_configured" };

  try {
    const url = `https://api.github.com/repos/${cfg.repo}/contents/${opts.path}`;
    const res = await fetch(url, {
      method: "PUT",
      headers: {
        authorization: `Bearer ${cfg.token}`,
        accept: "application/vnd.github+json",
        "x-github-api-version": "2022-11-28",
        "content-type": "application/json",
        "user-agent": "dr-ohood-security-admin"
      },
      body: JSON.stringify({
        message: opts.message,
        content: Buffer.from(opts.content, "utf8").toString("base64"),
        sha: opts.sha,
        branch: cfg.branch
      })
    });

    if (!res.ok) {
      return { ok: false, error: `github_put_${res.status}` };
    }

    return { ok: true };
  } catch (error) {
    return {
      ok: false,
      error: error && error.message ? error.message : "github_put_failed"
    };
  }
}

/**
 * @param {'ip'|'provider'|'asn'|'fingerprint'} type
 * @param {string} value
 * @returns {Promise<{ ok: true, already: boolean } | { ok: false, error: string }>}
 */
export async function addToBlacklist(type, value) {
  const trimmed = String(value || "").trim();
  if (!trimmed) return { ok: false, error: "empty_value" };

  /** @type {Record<string, { file: string, key: string|null }>} */
  const map = {
    ip: { file: "ip-blacklist.json", key: "ips" },
    provider: { file: "provider-blacklist.json", key: "providers" },
    asn: { file: "asn-blacklist.json", key: "asns" },
    fingerprint: { file: "fingerprint-blacklist.json", key: null }
  };

  const spec = map[type];
  if (!spec) return { ok: false, error: "invalid_type" };

  const path = securityFilePath(spec.file);
  const current = await getGithubJsonFile(path);
  if (!current.ok) return { ok: false, error: current.error };

  let nextJson;
  let already = false;

  if (spec.key === null) {
    // fingerprint-blacklist.json is a raw array
    const list = Array.isArray(current.json) ? [...current.json] : [];
    if (list.includes(trimmed)) {
      already = true;
      nextJson = list;
    } else {
      nextJson = [...list, trimmed];
    }
  } else {
    const obj =
      current.json && typeof current.json === "object" ? { ...current.json } : {};
    const list = Array.isArray(obj[spec.key]) ? [...obj[spec.key]] : [];
    if (list.includes(trimmed)) {
      already = true;
    } else {
      list.push(trimmed);
      if (type === "ip") {
        list.sort((a, b) => {
          const pa = a.split(".").map(Number);
          const pb = b.split(".").map(Number);
          for (let i = 0; i < 4; i++) {
            if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0);
          }
          return 0;
        });
      }
    }
    obj[spec.key] = list;
    nextJson = obj;
  }

  if (already) return { ok: true, already: true };

  const content = `${JSON.stringify(nextJson, null, 2)}\n`;
  const put = await putGithubFile({
    path,
    content,
    sha: current.sha,
    message: `security: block ${type} ${trimmed}`
  });

  if (!put.ok) return { ok: false, error: put.error };
  return { ok: true, already: false };
}
