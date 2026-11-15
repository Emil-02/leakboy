"use client";

import { useCallback, useEffect, useState, type ReactNode } from "react";
import type { Finding, ScanResult, Severity } from "leakboy";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

/** Tiny markdown subset for fixes: fenced code, inline code, bold, links. No raw HTML. */
function renderMarkdown(md: string): ReactNode[] {
  const out: ReactNode[] = [];
  const parts = md.split(/```[a-z]*\n?/);
  parts.forEach((part, i) => {
    if (i % 2 === 1) {
      out.push(
        <pre key={i}>
          <code>{part.replace(/\n$/, "")}</code>
        </pre>,
      );
      return;
    }
    part
      .split(/\n{2,}/)
      .filter((p) => p.trim())
      .forEach((para, j) => out.push(<p key={`${i}-${j}`}>{inline(para)}</p>));
  });
  return out;
}

function inline(text: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  const re = /(`[^`]+`|\*\*[^*]+\*\*|https?:\/\/[^\s)]+)/g;
  let last = 0;
  let k = 0;
  for (const m of text.matchAll(re)) {
    const idx = m.index ?? 0;
    if (idx > last) nodes.push(text.slice(last, idx));
    const tok = m[0];
    if (tok.startsWith("`")) nodes.push(<code key={k++}>{tok.slice(1, -1)}</code>);
    else if (tok.startsWith("**")) nodes.push(<strong key={k++}>{tok.slice(2, -2)}</strong>);
    else
      nodes.push(
        <a key={k++} href={tok} target="_blank" rel="noreferrer noopener">
          {tok}
        </a>,
      );
    last = idx + tok.length;
  }
  if (last < text.length) nodes.push(text.slice(last));
  return nodes;
}

function FindingItem({ f }: { f: Finding }) {
  return (
    <li>
      <details>
        <summary>
          <span className={`sev ${f.severity}`}>{f.severity}</span>
          <span>{f.title}</span>
        </summary>
        <div className="body">
          {f.location && <div className="loc">{f.location}</div>}
          {f.evidence && (
            <div className="loc">
              evidence (masked): <code>{f.evidence}</code>
            </div>
          )}
          <p>{inline(f.detail)}</p>
          {f.fix && (
            <>
              <strong>Fix</strong>
              {renderMarkdown(f.fix)}
            </>
          )}
          {f.links?.map((l) => (
            <div key={l} className="loc">
              ↳{" "}
              <a href={l} target="_blank" rel="noreferrer noopener">
                {l}
              </a>
            </div>
          ))}
        </div>
      </details>
    </li>
  );
}

function Report({ r, origin }: { r: ScanResult; origin: string }) {
  const counts = SEVERITIES.map((s) => [s, r.findings.filter((f) => f.severity === s).length] as const).filter(([, n]) => n);
  const shareUrl = `${origin}/?url=${encodeURIComponent(r.target)}`;
  const badge = `[![leakboy](${origin}/api/badge?url=${encodeURIComponent(r.target)})](${shareUrl})`;
  const [copied, setCopied] = useState("");
  const copy = (text: string, what: string) => {
    void navigator.clipboard.writeText(text).then(() => {
      setCopied(what);
      setTimeout(() => setCopied(""), 1500);
    });
  };
  return (
    <div className="report">
      <div className="summary">
        <div className={`grade ${r.score.grade}`}>{r.score.grade}</div>
        <div>
          <h2>
            {r.score.score}/100 · {r.target}
          </h2>
          <div className="meta">
            {[
              r.detected.frameworks.join(", "),
              r.detected.supabase.length ? "Supabase" : "",
              r.detected.firebase.length ? "Firebase" : "",
              `${r.stats.scripts} scripts`,
              `${r.stats.requests} requests`,
              `${(r.durationMs / 1000).toFixed(1)}s`,
            ]
              .filter(Boolean)
              .join(" · ")}
          </div>
          <div className="counts">
            {counts.length ? (
              counts.map(([s, n]) => (
                <span key={s} className={`sev ${s}`}>
                  {n} {s}
                </span>
              ))
            ) : (
              <span className="sev" style={{ color: "var(--ok)" }}>
                no leaks found
              </span>
            )}
          </div>
        </div>
      </div>
      <ul className="findings">
        {r.findings.map((f, i) => (
          <FindingItem key={`${f.ruleId}-${i}`} f={f} />
        ))}
      </ul>
      <div className="passed">
        {r.checks
          .filter((c) => c.status === "pass")
          .map((c) => (
            <span key={c.id}>{c.title}</span>
          ))}
      </div>
      <div className="share">
        <div className="share-row">
          <strong>Share / add to your README</strong>
          <button className="ghost" onClick={() => copy(shareUrl, "link")}>
            {copied === "link" ? "Copied!" : "Copy link"}
          </button>
          <button className="ghost" onClick={() => copy(badge, "badge")}>
            {copied === "badge" ? "Copied!" : "Copy badge markdown"}
          </button>
        </div>
        <pre>{badge}</pre>
      </div>
    </div>
  );
}

export function Scanner() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [origin, setOrigin] = useState("");

  const run = useCallback(async (target: string) => {
    if (!target.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);
    window.history.replaceState(null, "", `/?url=${encodeURIComponent(target.trim())}`);
    try {
      const res = await fetch(`/api/scan?url=${encodeURIComponent(target.trim())}`);
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
      setResult(body as ScanResult);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    setOrigin(window.location.origin);
    const initial = new URLSearchParams(window.location.search).get("url");
    if (initial) {
      setUrl(initial);
      void run(initial);
    }
  }, [run]);

  return (
    <>
      <form
        className="scan"
        onSubmit={(e) => {
          e.preventDefault();
          void run(url);
        }}
      >
        <input
          type="text"
          inputMode="url"
          placeholder="https://your-app.vercel.app"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          aria-label="URL to scan"
          required
        />
        <button type="submit" disabled={loading}>
          {loading ? "Scanning…" : "Scan"}
        </button>
      </form>
      <div className="note">Passive and read-only. Takes 5–40 seconds. Only scan apps you own or may test.</div>
      {!result && !loading && !error && (
        <ul className="chips">
          <li>Next.js</li>
          <li>Vite / React</li>
          <li>Lovable</li>
          <li>Bolt</li>
          <li>v0</li>
          <li>Nuxt</li>
          <li>SvelteKit</li>
          <li>Supabase</li>
          <li>Firebase</li>
        </ul>
      )}
      {loading && <div className="loading">🤠 Downloading your bundles and poking your backend (read-only)…</div>}
      {error && <div className="error">{error}</div>}
      {result && <Report r={result} origin={origin} />}
    </>
  );
}
