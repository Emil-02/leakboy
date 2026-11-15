import type { HttpClient, HttpResponse } from "../http.js";
import type { ProbeContext } from "./supabase.js";
import type { Severity } from "../types.js";

interface ExposureRule {
  path: string;
  id: string;
  title: string;
  severity: Severity;
  /** Returns a short, value-free description when the response really is that file. */
  match: (res: HttpResponse) => string | undefined;
  fix: string;
}

const isHtml = (res: HttpResponse) =>
  (res.headers.get("content-type") ?? "").includes("text/html") || /^\s*<(!doctype|html|head|body)/i.test(res.text().slice(0, 300));

const ENV_LINE = /^\s*(?:export\s+)?([A-Z][A-Z0-9_]{1,80})\s*=/gm;

function envKeys(res: HttpResponse): string | undefined {
  if (isHtml(res)) return undefined;
  const keys = [...res.text().matchAll(ENV_LINE)].map((m) => m[1] as string);
  if (keys.length === 0) return undefined;
  const shown = keys.slice(0, 12).join(", ");
  return `${keys.length} variable(s): ${shown}${keys.length > 12 ? ", …" : ""} (values not shown)`;
}

const ENV_FIX =
  "Delete the file from the web root and redeploy, then **rotate every secret in it**. Make sure your host only serves the build output (`dist/`, `.next/`, `public/`), never the project root.";

export const EXPOSURE_RULES: ExposureRule[] = [
  ...[".env", ".env.local", ".env.production", ".env.development", ".env.prod", ".env.backup"].map(
    (name): ExposureRule => ({
      path: `/${name}`,
      id: "exposure/env-file",
      title: `${name} file is publicly downloadable`,
      severity: "critical",
      match: envKeys,
      fix: ENV_FIX,
    }),
  ),
  {
    path: "/.git/config",
    id: "exposure/git",
    title: ".git directory is publicly downloadable",
    severity: "high",
    match: (res) => {
      const t = res.text();
      if (isHtml(res) || !/\[core\]/.test(t)) return undefined;
      const tokenInRemote = /url\s*=\s*https?:\/\/[^@\s]+:[^@\s]+@/.test(t);
      return tokenInRemote
        ? "The git config contains a remote URL with embedded credentials, and the full source code and history can be reconstructed."
        : "The full source code and commit history (including deleted secrets) can be reconstructed with tools like git-dumper.";
    },
    fix: "Block `/.git` on your web server or remove it from the deployed folder. Rotate any secret that was ever committed.",
  },
  {
    path: "/.npmrc",
    id: "exposure/npmrc",
    title: ".npmrc is publicly downloadable",
    severity: "high",
    match: (res) =>
      !isHtml(res) && /registry|_authToken|always-auth/.test(res.text())
        ? /_authToken/.test(res.text())
          ? "It contains an npm auth token (value not shown)."
          : "It reveals registry configuration."
        : undefined,
    fix: "Remove `.npmrc` from the web root and revoke any token it contained.",
  },
  ...["/backup.sql", "/dump.sql", "/database.sql", "/db.sql"].map(
    (path): ExposureRule => ({
      path,
      id: "exposure/sql-dump",
      title: `Database dump ${path} is publicly downloadable`,
      severity: "critical",
      match: (res) =>
        !isHtml(res) && /\b(CREATE TABLE|INSERT INTO|PostgreSQL database dump|MySQL dump)\b/i.test(res.text())
          ? "The file looks like a SQL dump (contents not shown)."
          : undefined,
      fix: "Delete the dump from the web root now and treat all data in it as leaked.",
    }),
  ),
  {
    path: "/docker-compose.yml",
    id: "exposure/docker-compose",
    title: "docker-compose.yml is publicly downloadable",
    severity: "medium",
    match: (res) =>
      !isHtml(res) && /^\s*services\s*:/m.test(res.text())
        ? /PASSWORD|SECRET|TOKEN|KEY/i.test(res.text())
          ? "It defines services and mentions passwords/secrets (values not shown)."
          : "It reveals your infrastructure layout."
        : undefined,
    fix: "Only deploy the build output, not infrastructure files.",
  },
  {
    path: "/.DS_Store",
    id: "exposure/ds-store",
    title: ".DS_Store file is public",
    severity: "low",
    match: (res) =>
      res.body.length > 8 && res.body.subarray(4, 8).toString("latin1") === "Bud1"
        ? "It lists the names of files and folders in your deploy directory."
        : undefined,
    fix: "Add `.DS_Store` to `.gitignore` and remove it from the deployment.",
  },
];

export async function checkExposure(http: HttpClient, origin: string, ctx: ProbeContext): Promise<void> {
  ctx.onProgress?.("Checking for exposed files");
  let failed = 0;
  let checked = 0;
  for (const rule of EXPOSURE_RULES) {
    if (http.remainingRequests <= 2) break;
    try {
      const res = await http.request(new URL(rule.path, origin).toString(), { maxBytes: 128 * 1024, followRedirects: false });
      checked++;
      if (res.status !== 200) continue;
      const detail = rule.match(res);
      if (!detail) continue;
      failed++;
      ctx.findings.push({
        ruleId: rule.id,
        severity: rule.severity,
        category: "exposure",
        title: rule.title,
        detail,
        location: new URL(rule.path, origin).toString(),
        fix: rule.fix,
      });
    } catch (err) {
      ctx.errors.push(`${rule.path}: ${(err as Error).message}`);
      if ((err as Error).name === "BudgetExceededError") break;
    }
  }
  ctx.checks.push({
    id: "exposure/files",
    category: "exposure",
    title: "No exposed .env/.git/dumps",
    status: failed ? "fail" : checked ? "pass" : "skip",
    note: `${checked} path(s) checked.`,
  });
}

export async function checkHeaders(http: HttpClient, page: HttpResponse, ctx: ProbeContext): Promise<void> {
  const h = page.headers;
  const url = new URL(page.url);
  const local = /^(localhost|127\.|\[::1\])/.test(url.hostname);
  const add = (id: string, severity: Severity, title: [pass: string, fail: string], detail: string, fix: string, pass: boolean) => {
    ctx.checks.push({ id: `headers/${id}`, category: "headers", title: title[0], status: pass ? "pass" : "fail" });
    if (!pass) {
      ctx.findings.push({ ruleId: `headers/${id}`, severity, category: "headers", title: title[1], detail, location: page.url, fix });
    }
  };

  if (!local) {
    add(
      "https",
      "medium",
      ["Served over HTTPS", "Site is served over plain HTTP"],
      "The page is served over plain HTTP, so logins and API keys travel unencrypted.",
      "Serve the site over HTTPS only and redirect HTTP to HTTPS.",
      url.protocol === "https:",
    );
  }
  if (url.protocol === "https:") {
    add(
      "hsts",
      "low",
      ["HSTS enabled", "Missing Strict-Transport-Security (HSTS) header"],
      "Without HSTS a network attacker can downgrade the first visit to HTTP.",
      "Add `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`.",
      h.has("strict-transport-security"),
    );
  }
  const csp = h.get("content-security-policy") ?? "";
  add(
    "csp",
    "low",
    ["Content-Security-Policy set", "Missing Content-Security-Policy header"],
    "A CSP limits the damage of an XSS bug, for example by blocking stolen tokens from being sent to other domains.",
    "Start with `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'` and loosen it as needed. Next.js has a guide: https://nextjs.org/docs/app/guides/content-security-policy",
    csp.length > 0,
  );
  add(
    "clickjacking",
    "low",
    ["Clickjacking protection", "No clickjacking protection"],
    "Other sites can load your app in an invisible iframe and trick users into clicking buttons.",
    "Send `X-Frame-Options: DENY` or `Content-Security-Policy: frame-ancestors 'none'`.",
    h.has("x-frame-options") || /frame-ancestors/.test(csp),
  );
  add(
    "nosniff",
    "info",
    ["nosniff set", "Missing X-Content-Type-Options: nosniff"],
    "Browsers may guess content types of uploads and execute them.",
    "Send `X-Content-Type-Options: nosniff`.",
    (h.get("x-content-type-options") ?? "").toLowerCase() === "nosniff",
  );

  try {
    const evil = "https://evil.leakboy.invalid";
    const res = await http.request(page.url, { headers: { origin: evil }, maxBytes: 1024 });
    const acao = res.headers.get("access-control-allow-origin");
    const creds = res.headers.get("access-control-allow-credentials") === "true";
    const reflected = acao === evil && creds;
    add(
      "cors",
      "high",
      ["CORS locked down", "CORS trusts any origin with credentials"],
      "The server reflects any Origin and allows credentials, so any website can make logged-in requests on behalf of your users and read the answers.",
      "Only allow your own origins in `Access-Control-Allow-Origin`, and never combine a reflected origin with `Access-Control-Allow-Credentials: true`.",
      !reflected,
    );
  } catch (err) {
    ctx.errors.push(`cors check: ${(err as Error).message}`);
  }
}
