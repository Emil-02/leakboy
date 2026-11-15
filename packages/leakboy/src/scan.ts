import { stat } from "node:fs/promises";
import { resolve } from "node:path";
import { crawl, type SourceFile } from "./crawler.js";
import { detect, publicSupabase, scanSecrets, type Detection } from "./detect.js";
import { HttpClient, type HttpOptions } from "./http.js";
import { collectLocal } from "./local.js";
import { probeFirebase } from "./probes/firebase.js";
import { checkExposure, checkHeaders } from "./probes/exposure.js";
import { probeSupabase, type ProbeContext } from "./probes/supabase.js";
import { computeScore, sortFindings } from "./score.js";
import {
  CATEGORIES,
  DEFAULT_ENDPOINTS,
  type Category,
  type Check,
  type Finding,
  type ScanOptions,
  type ScanResult,
} from "./types.js";
import { VERSION } from "./version.js";

function httpOptions(o: ScanOptions): HttpOptions {
  return {
    allowPrivateNetworks: o.allowPrivateNetworks ?? false,
    standardPortsOnly: o.standardPortsOnly ?? false,
    timeoutMs: o.timeoutMs ?? 10_000,
    maxRequests: o.maxRequests ?? 250,
    maxResponseBytes: o.maxResponseBytes ?? 8 * 1024 * 1024,
    maxTotalBytes: o.maxTotalBytes ?? 60 * 1024 * 1024,
    deadline: o.maxDurationMs ? Date.now() + o.maxDurationMs : undefined,
  };
}

/** Accepts `example.com`, `https://example.com/path` or a local folder. */
export async function isLocalTarget(target: string): Promise<boolean> {
  if (/^https?:\/\//i.test(target)) return false;
  try {
    return (await stat(target)).isDirectory();
  } catch {
    return false;
  }
}

export function normalizeUrl(target: string): string {
  const withScheme = /^https?:\/\//i.test(target) ? target : `https://${target}`;
  const url = new URL(withScheme);
  url.hash = "";
  return url.toString();
}

function sourceMapFinding(maps: Array<{ url: string; sources: number }>, local: boolean): Finding {
  const files = maps.reduce((s, m) => s + m.sources, 0);
  return {
    ruleId: "secrets/source-maps",
    severity: local ? "low" : "medium",
    category: "secrets",
    title: local ? `${maps.length} source map(s) in client build output` : `${maps.length} source map(s) are public`,
    detail:
      (local
        ? "These maps will be downloadable once deployed. "
        : "Anyone can rebuild your original source code from them. ") +
      `They contain ${files} original file(s): comments, internal endpoints, admin routes and any hard-coded keys become readable.`,
    location: maps[0]?.url,
    evidence: maps.length > 1 ? `${maps[0]?.url} (+${maps.length - 1} more)` : undefined,
    fix:
      "Disable browser source maps in production (`productionBrowserSourceMaps: false` in Next.js, `build.sourcemap: false` or `'hidden'` in Vite) or upload them to your error tracker and delete them from the deploy.",
  };
}

async function runProbes(det: Detection, ctx: ProbeContext, opts: ScanOptions, want: (c: Category) => boolean) {
  if (opts.noProbe) {
    if (det.supabase.length || det.firebase.length) {
      ctx.checks.push({ id: "probe/skipped", category: "supabase", title: "Backend probes", status: "skip", note: "--no-probe" });
    }
    return;
  }
  if (want("supabase")) for (const cfg of det.supabase.slice(0, 3)) await probeSupabase(cfg, det, ctx);
  if (want("firebase")) {
    const endpoints = { ...DEFAULT_ENDPOINTS, ...opts.endpoints };
    for (const cfg of det.firebase.slice(0, 3)) await probeFirebase(cfg, det, endpoints, ctx);
  }
}

/**
 * Scans a deployed URL or a local build folder.
 * Everything is read-only: leakboy never writes data, and never prints row contents or full secrets.
 */
export async function scan(target: string, opts: ScanOptions = {}): Promise<ScanResult> {
  const started = Date.now();
  const only = opts.only?.length ? opts.only : CATEGORIES;
  const want = (c: Category) => only.includes(c);
  const findings: Finding[] = [];
  const checks: Check[] = [];
  const errors: string[] = [];
  const http = new HttpClient(httpOptions(opts));
  const ctx: ProbeContext = { http, findings, checks, errors, onProgress: opts.onProgress };
  const local = await isLocalTarget(target);
  let files: SourceFile[] = [];
  let frameworks: string[] = [];
  let resolvedTarget = target;

  try {
    if (local) {
      resolvedTarget = resolve(target);
      opts.onProgress?.(`Reading ${resolvedTarget}`);
      const res = await collectLocal(resolvedTarget);
      files = res.files;
      http.stats.scripts = files.filter((f) => f.kind === "js").length;
      http.stats.sourceMaps = res.clientSourceMaps.length;
      if (want("secrets") && res.clientSourceMaps.length) {
        findings.push(sourceMapFinding(res.clientSourceMaps.map((url) => ({ url, sources: 0 })), true));
      }
    } else {
      resolvedTarget = normalizeUrl(target);
      const crawled = await crawl(http, resolvedTarget, {
        maxScripts: opts.maxScripts ?? 80,
        maxMapProbes: 3,
        onProgress: opts.onProgress,
      });
      resolvedTarget = crawled.finalUrl;
      files = crawled.files;
      frameworks = crawled.frameworks;
      errors.push(...crawled.errors);
      if (want("secrets") && crawled.sourceMaps.length) findings.push(sourceMapFinding(crawled.sourceMaps, false));
      if (want("headers") && crawled.page) await checkHeaders(http, crawled.page, ctx);
      if (want("exposure")) await checkExposure(http, new URL(resolvedTarget).origin, ctx);
    }

    if (want("secrets")) {
      opts.onProgress?.(`Scanning ${files.length} file(s) for secrets`);
      const secrets = scanSecrets(files);
      findings.push(...secrets);
      checks.push({
        id: "secrets/bundle",
        category: "secrets",
        title: "No secrets in client code",
        status: secrets.length ? "fail" : "pass",
        note: `${files.length} file(s) scanned.`,
      });
    }

    const det = detect(files);
    await runProbes(det, ctx, opts, want);

    const score = computeScore(findings);
    return {
      tool: { name: "leakboy", version: VERSION },
      target: resolvedTarget,
      mode: local ? "local" : "url",
      startedAt: new Date(started).toISOString(),
      durationMs: Date.now() - started,
      score,
      findings: sortFindings(findings),
      checks,
      detected: { supabase: publicSupabase(det), firebase: det.firebase.map(({ apiKey, ...f }) => ({ ...f, apiKey: apiKey ? `${apiKey.slice(0, 8)}…` : undefined })), frameworks },
      stats: { ...http.stats },
      errors,
    };
  } finally {
    await http.close();
  }
}
