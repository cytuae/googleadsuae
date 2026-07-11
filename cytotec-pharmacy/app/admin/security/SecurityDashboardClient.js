"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

function RowActions({ row, onBlock, busy }) {
  return (
    <div className="actions">
      <button
        type="button"
        disabled={busy || !row.ip}
        onClick={() => onBlock("ip", row.ip)}
      >
        Block IP
      </button>
      <button
        type="button"
        disabled={busy || !row.visitorId}
        onClick={() => onBlock("fingerprint", row.visitorId)}
      >
        Block Fingerprint
      </button>
      <button
        type="button"
        disabled={busy || !row.asn}
        onClick={() => onBlock("asn", row.asn)}
      >
        Block ASN
      </button>
      <button
        type="button"
        disabled={busy || !row.provider}
        onClick={() => onBlock("provider", row.provider)}
      >
        Block Provider
      </button>
    </div>
  );
}

function Panel({ title, items }) {
  const list = Array.isArray(items) ? items : [];
  return (
    <div className="panel">
      <h3>{title}</h3>
      {list.length === 0 ? (
        <p className="muted small">None yet</p>
      ) : (
        <ul>
          {list.slice(0, 12).map((item) => (
            <li key={String(item)} className="mono">
              {String(item)}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function formatTime(ts) {
  if (!ts) return "—";
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return String(ts);
  }
}

export default function SecurityDashboardClient() {
  const [authed, setAuthed] = useState(false);
  const [password, setPassword] = useState("");
  const [loginError, setLoginError] = useState("");
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState(null);
  const [query, setQuery] = useState("");
  const [busy, setBusy] = useState(false);
  const [toast, setToast] = useState("");
  const [manualType, setManualType] = useState("ip");
  const [manualValue, setManualValue] = useState("");

  const loadData = useCallback(async () => {
    try {
      const res = await fetch("/api/admin/security/data", {
        credentials: "same-origin",
        cache: "no-store"
      });
      if (res.status === 401) {
        setAuthed(false);
        setData(null);
        return;
      }
      const json = await res.json();
      if (json && json.ok) {
        setAuthed(true);
        setData(json);
      }
    } catch {
      setToast("Failed to load data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  async function handleLogin(e) {
    e.preventDefault();
    setLoginError("");
    try {
      const res = await fetch("/api/admin/security/login", {
        method: "POST",
        credentials: "same-origin",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ password })
      });
      const json = await res.json();
      if (!res.ok || !json.ok) {
        setLoginError(
          json.error === "admin_not_configured"
            ? "Set SECURITY_ADMIN_PASSWORD on Vercel (min 8 chars)"
            : "Invalid password"
        );
        return;
      }
      setPassword("");
      setLoading(true);
      await loadData();
    } catch {
      setLoginError("Login failed");
    }
  }

  async function handleLogout() {
    await fetch("/api/admin/security/logout", {
      method: "POST",
      credentials: "same-origin"
    });
    setAuthed(false);
    setData(null);
  }

  async function onBlock(type, value) {
    if (!value) return;
    setBusy(true);
    setToast("");
    try {
      const res = await fetch("/api/admin/security/block", {
        method: "POST",
        credentials: "same-origin",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ type, value })
      });
      const json = await res.json();
      if (!res.ok || !json.ok) {
        setToast(json.message || json.error || "Block failed");
      } else {
        setToast(json.message || "Blocked");
        await loadData();
      }
    } catch {
      setToast("Block failed");
    } finally {
      setBusy(false);
    }
  }

  async function handleManualBlock(e) {
    e.preventDefault();
    await onBlock(manualType, manualValue.trim());
    setManualValue("");
  }

  const events = data?.events || [];
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return events;
    return events.filter((row) =>
      JSON.stringify(row).toLowerCase().includes(q)
    );
  }, [events, query]);

  const latest = data?.latest || {};

  return (
    <>
      <style>{css}</style>
      {loading ? (
        <div className="wrap">
          <p className="muted">Loading…</p>
        </div>
      ) : !authed ? (
        <div className="wrap center">
          <form className="card login" onSubmit={handleLogin}>
            <h1>Security Admin</h1>
            <p className="muted">Private — password required</p>
            <input
              type="password"
              autoComplete="current-password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
            {loginError ? <p className="err">{loginError}</p> : null}
            <button type="submit">Sign in</button>
          </form>
        </div>
      ) : (
        <div className="wrap">
          <header className="top">
            <div>
              <h1>Security Dashboard</h1>
              <p className="muted">
                {data?.generatedAt
                  ? `Updated ${new Date(data.generatedAt).toLocaleString()}`
                  : ""}
                {data?.githubConfigured
                  ? " · GitHub sync on"
                  : " · Set GITHUB_TOKEN to enable auto-blacklist updates"}
              </p>
            </div>
            <div className="top-actions">
              <button type="button" onClick={() => loadData()}>
                Refresh
              </button>
              <button type="button" className="ghost" onClick={handleLogout}>
                Logout
              </button>
            </div>
          </header>

          {toast ? <p className="toast">{toast}</p> : null}

          <section className="grid">
            <Panel title="1. Latest blocked IPs" items={latest.ips} />
            <Panel
              title="2. Latest blocked fingerprints"
              items={latest.fingerprints}
            />
            <Panel title="3. Latest providers" items={latest.providers} />
            <Panel title="4. Latest ASN" items={latest.asns} />
            <Panel title="5. Latest countries" items={latest.countries} />
            <Panel title="6. Latest browsers" items={latest.browsers} />
            <Panel title="7. Latest devices" items={latest.devices} />
            <Panel title="8. Block reasons" items={latest.reasons} />
          </section>

          <section className="card">
            <h2>Manual block</h2>
            <form className="manual" onSubmit={handleManualBlock}>
              <select
                value={manualType}
                onChange={(e) => setManualType(e.target.value)}
              >
                <option value="ip">IP</option>
                <option value="fingerprint">Fingerprint</option>
                <option value="asn">ASN</option>
                <option value="provider">Provider</option>
              </select>
              <input
                value={manualValue}
                onChange={(e) => setManualValue(e.target.value)}
                placeholder="Value to block"
                required
              />
              <button type="submit" disabled={busy}>
                Block
              </button>
            </form>
            <p className="muted small">
              Buttons update security/*-blacklist.json via GitHub automatically.
              Vercel redeploys so enforcement picks up the change.
            </p>
          </section>

          <section className="card">
            <div className="table-head">
              <h2>9. Search / events</h2>
              <input
                className="search"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search IP, fingerprint, ASN, country, browser…"
              />
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>IP</th>
                    <th>Fingerprint</th>
                    <th>Provider</th>
                    <th>ASN</th>
                    <th>Country</th>
                    <th>Browser</th>
                    <th>Device</th>
                    <th>Reason</th>
                    <th>10. Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.length === 0 ? (
                    <tr>
                      <td colSpan={10} className="muted">
                        No events yet. After GITHUB_TOKEN is set, blocked visits
                        sync into this log.
                      </td>
                    </tr>
                  ) : (
                    filtered.map((row, idx) => (
                      <tr key={`${row.timestamp}-${row.ip}-${idx}`}>
                        <td>{formatTime(row.timestamp)}</td>
                        <td className="mono">{row.ip || "—"}</td>
                        <td className="mono trunc" title={row.visitorId || ""}>
                          {row.visitorId || "—"}
                        </td>
                        <td>{row.provider || row.company || "—"}</td>
                        <td className="mono">{row.asn || "—"}</td>
                        <td>{row.country || "—"}</td>
                        <td>{row.browser || "—"}</td>
                        <td>{row.device || "—"}</td>
                        <td>{row.reason || "—"}</td>
                        <td>
                          <RowActions
                            row={{
                              ...row,
                              provider: row.provider || row.company
                            }}
                            onBlock={onBlock}
                            busy={busy}
                          />
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </section>

          <section className="card">
            <h2>Current blacklists</h2>
            <div className="grid">
              <Panel
                title={`IPs (${data?.blacklists?.ips?.length || 0})`}
                items={[...(data?.blacklists?.ips || [])].reverse().slice(0, 30)}
              />
              <Panel
                title={`Fingerprints (${data?.blacklists?.fingerprints?.length || 0})`}
                items={data?.blacklists?.fingerprints || []}
              />
              <Panel
                title={`Providers (${data?.blacklists?.providers?.length || 0})`}
                items={data?.blacklists?.providers || []}
              />
              <Panel
                title={`ASNs (${data?.blacklists?.asns?.length || 0})`}
                items={data?.blacklists?.asns || []}
              />
            </div>
          </section>
        </div>
      )}
    </>
  );
}

const css = `
  .wrap {
    min-height: 100dvh;
    padding: 1.25rem;
    max-width: 1400px;
    margin: 0 auto;
    font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif;
    background: #0b0d10;
    color: #e8eaed;
  }
  .center { display: grid; place-items: center; min-height: 100dvh; }
  h1 { margin: 0 0 0.25rem; font-size: 1.35rem; }
  h2 { margin: 0 0 0.75rem; font-size: 1.05rem; }
  h3 { margin: 0 0 0.5rem; font-size: 0.85rem; color: #9aa3af; font-weight: 600; }
  .muted { color: #9aa3af; margin: 0; }
  .small { font-size: 0.8rem; margin-top: 0.5rem; }
  .err { color: #f87171; margin: 0.5rem 0 0; }
  .toast {
    background: #14532d; color: #bbf7d0; padding: 0.6rem 0.8rem;
    border-radius: 8px; margin: 0 0 1rem;
  }
  .card {
    background: #12151a; border: 1px solid #1f2937;
    border-radius: 12px; padding: 1rem; margin-bottom: 1rem;
  }
  .login { width: min(360px, 100%); display: grid; gap: 0.75rem; }
  .login input, .manual input, .manual select, .search {
    width: 100%; box-sizing: border-box; background: #0b0d10;
    border: 1px solid #374151; color: #e8eaed; border-radius: 8px;
    padding: 0.65rem 0.75rem;
  }
  button {
    background: #2563eb; color: white; border: 0; border-radius: 8px;
    padding: 0.55rem 0.8rem; cursor: pointer; font-size: 0.8rem;
  }
  button:disabled { opacity: 0.4; cursor: not-allowed; }
  button.ghost { background: #1f2937; }
  .top {
    display: flex; justify-content: space-between; gap: 1rem;
    align-items: flex-start; margin-bottom: 1rem;
  }
  .top-actions { display: flex; gap: 0.5rem; }
  .grid {
    display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 0.75rem; margin-bottom: 1rem;
  }
  .panel {
    background: #12151a; border: 1px solid #1f2937;
    border-radius: 12px; padding: 0.85rem;
  }
  .panel ul { margin: 0; padding: 0; list-style: none; }
  .panel li { font-size: 0.78rem; padding: 0.2rem 0; word-break: break-all; }
  .manual { display: grid; grid-template-columns: 140px 1fr auto; gap: 0.5rem; }
  .table-head {
    display: flex; justify-content: space-between; gap: 1rem;
    align-items: center; margin-bottom: 0.75rem;
  }
  .search { max-width: 360px; }
  .table-wrap { overflow: auto; }
  table { width: 100%; border-collapse: collapse; font-size: 0.78rem; }
  th, td {
    text-align: left; padding: 0.45rem 0.4rem;
    border-bottom: 1px solid #1f2937; vertical-align: top;
  }
  th { color: #9aa3af; font-weight: 600; white-space: nowrap; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .trunc {
    max-width: 110px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  .actions { display: grid; gap: 0.25rem; }
  .actions button { padding: 0.3rem 0.45rem; font-size: 0.7rem; background: #374151; }
  @media (max-width: 800px) {
    .manual { grid-template-columns: 1fr; }
    .top { flex-direction: column; }
    .table-head { flex-direction: column; align-items: stretch; }
    .search { max-width: none; }
  }
`;
