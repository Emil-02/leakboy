import type { HttpClient, HttpResponse } from "./http.js";

export interface SourceFile {
  /** URL, `url#inline-1`, `url -> src/file.ts` (from a source map) or a local path. */
  location: string;
  content: string;
  kind: "html" | "inline" | "js" | "map-source" | "json" | "other";
}

export interface SourceMapHit {
  url: string;
  /** Script that referenced it. */
  script: string;
  sources: number;
  inline: boolean;
}

export interface CrawlResult {
  page?: HttpResponse;
  finalUrl: string;
  files: SourceFile[];
  sourceMaps: SourceMapHit[];
  frameworks: string[];
  errors: string[];
}

export interface CrawlOptions {
  maxScripts: number;
  maxMapProbes: number;
  onProgress?: (message: string) => void;
}

const SCRIPT_SRC = /<script\b[^>]*?\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi;
const LINK_JS = /<link\b[^>]*?\bhref\s*=\s*["']([^"']+\.m?js(?:\?[^"']*)?)["'][^>]*>/gi;
const INLINE_SCRIPT = /<script\b(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)<\/script>/gi;
const CHUNK_REF =
  /["'`]((?:\.{1,2}\/|\/)?(?:_next\/static\/|static\/chunks\/|static\/js\/|assets\/|_nuxt\/|_app\/immutable\/|_astro\/|js\/)?[\w@~.\-/]*?[\w-]+\.m?js)(?:\?[^"'`\s\\]*)?\\?["'`]/g;
const SOURCE_MAP_COMMENT = /\/[/*][#@]\s*sourceMappingURL=([^\s'"*]+)/g;

const FRAMEWORK_HINTS: Array<[string, RegExp]> = [
  ["Next.js", /\/_next\/static\/|__NEXT_DATA__|self\.__next_f/],
  ["Nuxt", /\/_nuxt\/|__NUXT__/],
  ["SvelteKit", /\/_app\/immutable\//],
  ["Astro", /\/_astro\//],
  ["Gatsby", /___gatsby|\/page-data\//],
  ["Angular", /ng-version=/],
  ["Create React App", /\/static\/js\/main\.[0-9a-f]+\.js/],
  ["Vite", /\/assets\/index-[\w-]+\.js|type="module"[^>]*src="\/assets\//],
  ["Remix", /__remixContext|\/build\/_shared\//],
];

/** Third-party hosts we never download: their bundles are not the app's code. */
const THIRD_PARTY =
  /(^|\.)(googletagmanager\.com|google-analytics\.com|googleapis\.com|gstatic\.com|cloudflareinsights\.com|cloudflare\.com|jsdelivr\.net|unpkg\.com|cdnjs\.com|stripe\.com|facebook\.net|hotjar\.com|segment\.com|sentry-cdn\.com|intercom\.io|crisp\.chat|tawk\.to|vercel-insights\.com|vercel-scripts\.com|posthog\.com|clarity\.ms|doubleclick\.net|recaptcha\.net|youtube\.com|twitter\.com|x\.com|tiktok\.com|midtrans\.com)$/i;

function siteKey(host: string): string {
  const parts = host.split(".");
  return parts.slice(-2).join(".");
}

function isFirstParty(url: URL, origin: URL): boolean {
  if (url.host === origin.host) return true;
  if (THIRD_PARTY.test(url.hostname)) return false;
  return siteKey(url.hostname) === siteKey(origin.hostname);
}

export function detectFrameworks(html: string): string[] {
  const found = FRAMEWORK_HINTS.filter(([, re]) => re.test(html)).map(([name]) => name);
  if (found.includes("Next.js")) return found.filter((f) => f !== "Vite" && f !== "Create React App");
  return found;
}

export function extractScriptUrls(html: string, base: string): string[] {
  const out = new Set<string>();
  for (const re of [SCRIPT_SRC, LINK_JS]) {
    for (const m of html.matchAll(re)) {
      const raw = m[1]?.replace(/&amp;/g, "&");
      if (!raw || raw.startsWith("data:")) continue;
      try {
        out.add(new URL(raw, base).toString());
      } catch {
        /* ignore malformed */
      }
    }
  }
  return [...out];
}

export function extractInlineScripts(html: string): string[] {
  const out: string[] = [];
  for (const m of html.matchAll(INLINE_SCRIPT)) {
    const body = m[1]?.trim();
    if (body) out.push(body);
  }
  return out;
}

/** Finds references to other JS chunks inside a script so lazy-loaded routes are scanned too. */
export function extractChunkRefs(js: string, scriptUrl: string, origin: string): string[] {
  const out = new Set<string>();
  for (const m of js.matchAll(CHUNK_REF)) {
    const ref = m[1];
    if (!ref || ref.length > 300 || ref.includes("node_modules") || ref.includes("//")) continue;
    if (!/[/.]/.test(ref.replace(/\.m?js$/, ""))) continue;
    let resolved: string;
    try {
      if (ref.startsWith("/")) resolved = new URL(ref, origin).toString();
      else if (ref.startsWith("./") || ref.startsWith("../")) resolved = new URL(ref, scriptUrl).toString();
      else if (ref.startsWith("static/")) resolved = new URL(`/_next/${ref}`, origin).toString();
      else if (/^(?:_next|assets|_nuxt|_app|_astro)\//.test(ref)) resolved = new URL(`/${ref}`, origin).toString();
      else if (ref.includes("/")) resolved = new URL(ref, scriptUrl).toString();
      else continue;
    } catch {
      continue;
    }
    out.add(resolved);
  }
  return [...out];
}

export function extractSourceMapRefs(js: string, scriptUrl: string): Array<{ url: string; inline?: string }> {
  const out: Array<{ url: string; inline?: string }> = [];
  for (const m of js.matchAll(SOURCE_MAP_COMMENT)) {
    const ref = m[1];
    if (!ref) continue;
    if (ref.startsWith("data:")) {
      const b64 = /;base64,(.*)$/.exec(ref)?.[1];
      if (b64) out.push({ url: `${scriptUrl} (inline source map)`, inline: Buffer.from(b64, "base64").toString("utf8") });
      continue;
    }
    try {
      out.push({ url: new URL(ref, scriptUrl).toString() });
    } catch {
      /* ignore */
    }
  }
  return out;
}

interface RawSourceMap {
  version?: number;
  mappings?: string;
  sources?: string[];
  sourcesContent?: Array<string | null>;
}

export function parseSourceMap(text: string): RawSourceMap | undefined {
  try {
    const map = JSON.parse(text) as RawSourceMap;
    if (typeof map === "object" && map && typeof map.mappings === "string" && Array.isArray(map.sources)) return map;
  } catch {
    /* not a map */
  }
  return undefined;
}

/** Turns a source map into scannable files, skipping third-party dependencies. */
export function filesFromSourceMap(map: RawSourceMap, mapUrl: string): SourceFile[] {
  const files: SourceFile[] = [];
  const sources = map.sources ?? [];
  sources.forEach((src, i) => {
    const content = map.sourcesContent?.[i];
    if (!content || /node_modules|webpack\/runtime|\(webpack\)/.test(src)) return;
    files.push({ location: `${mapUrl} -> ${src.replace(/^webpack:\/\/[^/]*\//, "")}`, content, kind: "map-source" });
  });
  return files;
}

function looksLikeHtml(res: HttpResponse): boolean {
  const type = res.headers.get("content-type") ?? "";
  if (type.includes("text/html")) return true;
  return /^\s*<(!doctype|html)/i.test(res.text().slice(0, 200));
}

/** Thrown when the target answers with an error or a bot challenge instead of the app, so a score would be meaningless. */
export class TargetBlockedError extends Error {
  override name = "TargetBlockedError";
}

const CHALLENGES: Array<[string, (page: HttpResponse, head: string) => boolean]> = [
  ["Vercel Security Checkpoint (bot protection)", (p, h) => p.headers.get("x-vercel-mitigated") === "challenge" || /Vercel Security Checkpoint/i.test(h)],
  ["Vercel Deployment Protection (login required)", (p, h) => p.status === 401 && /vercel/i.test(p.headers.get("server") ?? "") && /Authentication Required|vercel\.com\/sso/i.test(h)],
  ["Cloudflare challenge", (p, h) => p.headers.has("cf-mitigated") || /<title>Just a moment\.\.\.<\/title>|challenges\.cloudflare\.com\/cdn-cgi|cf-chl-/i.test(h)],
  ["Netlify password protection", (_p, h) => /netlify/i.test(h) && /password protected/i.test(h)],
];

/** Explains why a fetched page is not the real app, or returns undefined. */
export function blockedReason(page: HttpResponse): string | undefined {
  const head = page.text().slice(0, 20_000);
  const challenge = CHALLENGES.find(([, test]) => test(page, head))?.[0];
  if (challenge) return `${challenge}, HTTP ${page.status}`;
  if (page.status >= 400) return `HTTP ${page.status}`;
  return undefined;
}

export async function crawl(http: HttpClient, target: string, opts: CrawlOptions): Promise<CrawlResult> {
  const result: CrawlResult = { finalUrl: target, files: [], sourceMaps: [], frameworks: [], errors: [] };
  opts.onProgress?.(`Fetching ${target}`);
  const page = await http.request(target, { headers: { accept: "text/html,*/*" } });
  const blocked = blockedReason(page);
  if (blocked) {
    throw new TargetBlockedError(
      `${page.url} did not return the app (${blocked}), so leakboy cannot give a score. ` +
        "Bot protection stops simple scripts, but attackers can use real browsers, and your Supabase/API endpoints are usually not behind it. " +
        "Scan the build output instead (e.g. `npm run build && npx leakboy .next` or `npx leakboy dist`), " +
        "or scan a preview deployment/domain without the challenge.",
    );
  }
  result.page = page;
  result.finalUrl = page.url;
  const origin = new URL(page.url);
  const html = page.text();
  result.files.push({ location: page.url, content: html, kind: "html" });
  result.frameworks = detectFrameworks(html);
  extractInlineScripts(html).forEach((content, i) =>
    result.files.push({ location: `${page.url}#inline-${i + 1}`, content, kind: "inline" }),
  );

  const queue: string[] = [];
  const seen = new Set<string>();
  const enqueue = (u: string) => {
    if (seen.has(u)) return;
    try {
      if (!isFirstParty(new URL(u), origin)) return;
    } catch {
      return;
    }
    seen.add(u);
    queue.push(u);
  };
  extractScriptUrls(html, page.url).forEach(enqueue);
  for (const f of result.files) if (f.kind === "inline") extractChunkRefs(f.content, page.url, origin.origin).forEach(enqueue);

  const scripts: Array<{ url: string; content: string }> = [];
  while (queue.length && scripts.length < opts.maxScripts && http.remainingRequests > 10) {
    const url = queue.shift() as string;
    try {
      const res = await http.request(url);
      if (res.status !== 200 || looksLikeHtml(res)) continue;
      const content = res.text();
      scripts.push({ url, content });
      http.stats.scripts++;
      result.files.push({ location: url, content, kind: "js" });
      extractChunkRefs(content, url, origin.origin).forEach(enqueue);
    } catch (err) {
      result.errors.push((err as Error).message);
      if ((err as Error).name === "BudgetExceededError") break;
    }
  }
  opts.onProgress?.(`Downloaded ${scripts.length} script(s)`);

  const mapCandidates: Array<{ script: string; url: string; inline?: string }> = [];
  for (const s of scripts) {
    const refs = extractSourceMapRefs(s.content, s.url);
    refs.forEach((r) => mapCandidates.push({ script: s.url, ...r }));
  }
  // Source maps without a comment ("hidden") are still often deployed next to the script.
  const withoutComment = scripts
    .filter((s) => !mapCandidates.some((c) => c.script === s.url))
    .sort((a, b) => b.content.length - a.content.length)
    .slice(0, opts.maxMapProbes);
  for (const s of withoutComment) mapCandidates.push({ script: s.url, url: `${s.url.split("?")[0]}.map` });

  const seenMaps = new Set<string>();
  for (const c of mapCandidates) {
    if (seenMaps.has(c.url) || http.remainingRequests <= 5) continue;
    seenMaps.add(c.url);
    try {
      let text = c.inline;
      if (text === undefined) {
        const res = await http.request(c.url, { maxBytes: 20 * 1024 * 1024 });
        if (res.status !== 200 || looksLikeHtml(res)) continue;
        text = res.text();
      }
      const map = parseSourceMap(text);
      if (!map) continue;
      http.stats.sourceMaps++;
      const files = filesFromSourceMap(map, c.url);
      result.sourceMaps.push({ url: c.url, script: c.script, sources: map.sources?.length ?? 0, inline: c.inline !== undefined });
      result.files.push(...files);
    } catch (err) {
      result.errors.push((err as Error).message);
    }
  }
  if (result.sourceMaps.length) opts.onProgress?.(`Found ${result.sourceMaps.length} public source map(s)`);
  return result;
}
