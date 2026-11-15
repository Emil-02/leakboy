import { scan, normalizeUrl, type ScanResult } from "leakboy";

const TTL_MS = 10 * 60 * 1000;
const cache = new Map<string, { at: number; result: ScanResult }>();
const inflight = new Map<string, Promise<ScanResult>>();
const hits = new Map<string, number[]>();

export const RATE_LIMIT = { windowMs: 60_000, max: 6 };

export class UserError extends Error {
  constructor(
    message: string,
    readonly status = 400,
  ) {
    super(message);
  }
}

export function clientIp(req: Request): string {
  return req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || req.headers.get("x-real-ip") || "unknown";
}

/** Best-effort per-instance limiter; Vercel's CDN cache absorbs repeated scans of the same URL. */
export function rateLimit(ip: string): boolean {
  const now = Date.now();
  const recent = (hits.get(ip) ?? []).filter((t) => now - t < RATE_LIMIT.windowMs);
  if (recent.length >= RATE_LIMIT.max) {
    hits.set(ip, recent);
    return false;
  }
  recent.push(now);
  hits.set(ip, recent);
  if (hits.size > 5000) hits.clear();
  return true;
}

export function parseTarget(raw: string | null): string {
  if (!raw || raw.length > 2048) throw new UserError("Pass a URL, e.g. ?url=https://myapp.vercel.app");
  let url: string;
  try {
    url = normalizeUrl(raw.trim());
  } catch {
    throw new UserError("That does not look like a URL.");
  }
  const u = new URL(url);
  if (u.protocol !== "https:" && u.protocol !== "http:") throw new UserError("Only http(s) URLs can be scanned.");
  return `${u.protocol}//${u.host}${u.pathname}${u.search}`;
}

export async function scanCached(target: string): Promise<ScanResult> {
  const hit = cache.get(target);
  if (hit && Date.now() - hit.at < TTL_MS) return hit.result;
  const running = inflight.get(target);
  if (running) return running;
  const p = scan(target, {
    allowPrivateNetworks: process.env.LEAKBOY_WEB_ALLOW_PRIVATE === "1",
    standardPortsOnly: process.env.LEAKBOY_WEB_ALLOW_PRIVATE !== "1",
    timeoutMs: 8_000,
    maxRequests: 160,
    maxScripts: 60,
    maxTotalBytes: 30 * 1024 * 1024,
    maxDurationMs: 40_000,
  })
    .then((result) => {
      const trimmed: ScanResult = { ...result, errors: result.errors.slice(0, 10) };
      cache.set(target, { at: Date.now(), result: trimmed });
      if (cache.size > 300) cache.delete(cache.keys().next().value as string);
      return trimmed;
    })
    .finally(() => inflight.delete(target));
  inflight.set(target, p);
  return p;
}
