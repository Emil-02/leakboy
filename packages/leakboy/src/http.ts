import { BlockList, isIP } from "node:net";
import { lookup as dnsLookup, type LookupAddress } from "node:dns";
import { Agent, fetch, type Dispatcher } from "undici";
import type { ScanStats } from "./types.js";
import { VERSION } from "./version.js";

const blocked = new BlockList();
for (const [net, prefix] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
] as const) {
  blocked.addSubnet(net, prefix, "ipv4");
}
for (const [net, prefix] of [
  ["::", 128],
  ["::1", 128],
  ["64:ff9b::", 96],
  ["100::", 64],
  ["2001:db8::", 32],
  ["fc00::", 7],
  ["fe80::", 10],
  ["ff00::", 8],
] as const) {
  blocked.addSubnet(net, prefix, "ipv6");
}

/** True for loopback, private, link-local, CGNAT, multicast, documentation and other non-public addresses. */
export function isPrivateAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return blocked.check(address, "ipv4");
  if (family === 6) {
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
    if (mapped?.[1]) return blocked.check(mapped[1], "ipv4");
    return blocked.check(address, "ipv6");
  }
  return true;
}

export class BlockedTargetError extends Error {
  override name = "BlockedTargetError";
}

export class BudgetExceededError extends Error {
  override name = "BudgetExceededError";
}

export interface HttpOptions {
  allowPrivateNetworks: boolean;
  standardPortsOnly: boolean;
  timeoutMs: number;
  maxRequests: number;
  maxResponseBytes: number;
  maxTotalBytes: number;
  /** Epoch ms after which no new request is started. */
  deadline?: number;
}

export interface HttpResponse {
  url: string;
  status: number;
  headers: Headers;
  body: Buffer;
  truncated: boolean;
  text(): string;
  json<T = unknown>(): T | undefined;
}

export interface RequestOptions {
  method?: "GET" | "HEAD" | "POST";
  headers?: Record<string, string>;
  body?: string;
  maxBytes?: number;
  followRedirects?: boolean;
}

const USER_AGENT = `leakboy/${VERSION} (+https://github.com/Emil-02/leakboy)`;

function guardedLookup(
  hostname: string,
  options: object,
  callback: (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void,
): void {
  dnsLookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return callback(err, "");
    const list = addresses as LookupAddress[];
    const bad = list.find((a) => isPrivateAddress(a.address));
    if (bad) {
      const e: NodeJS.ErrnoException = new BlockedTargetError(
        `${hostname} resolves to a private address (${bad.address}); refusing to connect`,
      );
      e.code = "ELEAKBOYBLOCKED";
      return callback(e, "");
    }
    const all = (options as { all?: boolean }).all;
    if (all) return callback(null, list);
    const first = list[0];
    if (!first) return callback(new Error(`no address for ${hostname}`), "");
    callback(null, first.address, first.family);
  });
}

/**
 * A small HTTP client with a request/byte budget and SSRF protection.
 * When private networks are not allowed, every DNS answer is checked at connect time,
 * which also covers redirects and DNS rebinding.
 */
export class HttpClient {
  readonly stats: ScanStats = { requests: 0, scripts: 0, sourceMaps: 0, bytes: 0 };
  private readonly dispatcher: Dispatcher;

  constructor(private readonly opts: HttpOptions) {
    this.dispatcher = new Agent({
      connect: opts.allowPrivateNetworks ? { timeout: opts.timeoutMs } : { timeout: opts.timeoutMs, lookup: guardedLookup },
      headersTimeout: opts.timeoutMs,
      bodyTimeout: opts.timeoutMs,
    });
  }

  get remainingRequests(): number {
    if (this.opts.deadline && Date.now() > this.opts.deadline) return 0;
    return this.opts.maxRequests - this.stats.requests;
  }

  assertAllowed(raw: string): URL {
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      throw new BlockedTargetError(`invalid URL: ${raw}`);
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new BlockedTargetError(`only http(s) URLs are allowed: ${raw}`);
    }
    if (url.username || url.password) {
      throw new BlockedTargetError("URLs with credentials are not allowed");
    }
    if (this.opts.standardPortsOnly && url.port && url.port !== "80" && url.port !== "443") {
      throw new BlockedTargetError(`only ports 80 and 443 are allowed: ${url.host}`);
    }
    if (!this.opts.allowPrivateNetworks) {
      const host = url.hostname.replace(/^\[|\]$/g, "");
      if (isIP(host) && isPrivateAddress(host)) {
        throw new BlockedTargetError(`${host} is a private address; refusing to connect`);
      }
      if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".internal") || host.endsWith(".local")) {
        throw new BlockedTargetError(`${host} is a local hostname; refusing to connect`);
      }
    }
    return url;
  }

  async request(raw: string, options: RequestOptions = {}): Promise<HttpResponse> {
    let current = this.assertAllowed(raw).toString();
    const follow = options.followRedirects ?? true;
    for (let hop = 0; hop <= 5; hop++) {
      if (this.stats.requests >= this.opts.maxRequests) {
        throw new BudgetExceededError(`request budget of ${this.opts.maxRequests} reached`);
      }
      if (this.opts.deadline && Date.now() > this.opts.deadline) {
        throw new BudgetExceededError("time budget reached");
      }
      if (this.stats.bytes >= this.opts.maxTotalBytes) {
        throw new BudgetExceededError(`download budget of ${this.opts.maxTotalBytes} bytes reached`);
      }
      this.stats.requests++;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.opts.timeoutMs);
      try {
        const res = await fetch(current, {
          method: options.method ?? "GET",
          headers: { "user-agent": USER_AGENT, accept: "*/*", ...options.headers },
          body: options.body,
          redirect: "manual",
          signal: controller.signal,
          dispatcher: this.dispatcher,
        });
        if (follow && res.status >= 300 && res.status < 400 && res.headers.get("location")) {
          await res.body?.cancel().catch(() => undefined);
          current = this.assertAllowed(new URL(res.headers.get("location") as string, current).toString()).toString();
          continue;
        }
        const limit = Math.min(options.maxBytes ?? this.opts.maxResponseBytes, this.opts.maxTotalBytes - this.stats.bytes);
        const { body, truncated } = await readLimited(res.body, limit);
        this.stats.bytes += body.length;
        const headers = new Headers();
        res.headers.forEach((v, k) => headers.append(k, v));
        return makeResponse(current, res.status, headers, body, truncated);
      } catch (err) {
        if (err instanceof BudgetExceededError || err instanceof BlockedTargetError) throw err;
        const cause = (err as { cause?: { code?: string; message?: string } }).cause;
        if (cause?.code === "ELEAKBOYBLOCKED") throw new BlockedTargetError(cause.message ?? "blocked");
        if ((err as Error).name === "AbortError") throw new Error(`timeout after ${this.opts.timeoutMs} ms: ${current}`);
        throw new Error(`${(cause?.message ?? (err as Error).message) || "request failed"}: ${current}`);
      } finally {
        clearTimeout(timer);
      }
    }
    throw new Error(`too many redirects: ${raw}`);
  }

  async close(): Promise<void> {
    await this.dispatcher.close().catch(() => undefined);
  }
}

async function readLimited(
  stream: ReadableStream<Uint8Array> | null,
  limit: number,
): Promise<{ body: Buffer; truncated: boolean }> {
  if (!stream) return { body: Buffer.alloc(0), truncated: false };
  const reader = stream.getReader();
  const chunks: Buffer[] = [];
  let size = 0;
  let truncated = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    const remaining = limit - size;
    if (value.length > remaining) {
      if (remaining > 0) chunks.push(Buffer.from(value.subarray(0, remaining)));
      size += Math.max(remaining, 0);
      truncated = true;
      await reader.cancel().catch(() => undefined);
      break;
    }
    chunks.push(Buffer.from(value));
    size += value.length;
  }
  return { body: Buffer.concat(chunks), truncated };
}

export function makeResponse(url: string, status: number, headers: Headers, body: Buffer, truncated = false): HttpResponse {
  let textCache: string | undefined;
  return {
    url,
    status,
    headers,
    body,
    truncated,
    text() {
      textCache ??= body.toString("utf8");
      return textCache;
    },
    json<T>() {
      try {
        return JSON.parse(this.text()) as T;
      } catch {
        return undefined;
      }
    },
  };
}
