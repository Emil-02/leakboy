import type { SourceFile } from "./crawler.js";
import type { Finding, SupabaseTarget, FirebaseTarget } from "./types.js";
import { SECRET_RULES, decodeJwtPayload, maskSecret } from "./rules/secrets.js";

export interface SupabaseConfig extends SupabaseTarget {
  /** Full key, kept in memory only for probing. Never serialised. */
  rawKey: string;
}

export interface Detection {
  supabase: SupabaseConfig[];
  firebase: FirebaseTarget[];
  tables: Set<string>;
  buckets: Set<string>;
  rpcs: Set<string>;
  collections: Set<string>;
}

const SUPABASE_URL = /https:\/\/([a-z0-9]{20})\.supabase\.(?:co|in)\b/g;
const CREATE_CLIENT = /createClient\)?\(\s*["'`](https?:\/\/[^"'`\s]+)["'`]\s*,\s*["'`]([^"'`\s]+)["'`]/g;
const JWT = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g;
const PUBLISHABLE = /\bsb_publishable_[A-Za-z0-9_-]{20,}/g;
const TABLE_REF = /(?<!storage\s*)\.from\(\s*["'`]([A-Za-z_][\w$]{0,62})["'`]\s*\)/g;
const BUCKET_REF = /storage\s*\.from\(\s*["'`]([\w.-]{1,63})["'`]\s*\)/g;
const PUBLIC_BUCKET_URL = /\/storage\/v1\/object\/public\/([\w.-]{1,63})\//g;
const RPC_REF = /\.rpc\(\s*["'`]([A-Za-z_][\w]{0,62})["'`]/g;
const FS_COLLECTION = /(?:\bcollection|\bcollectionGroup)\(\s*[\w$.]+\s*,\s*["'`]([\w-]{1,100})["'`]|\.collection\(\s*["'`]([\w-]{1,100})["'`]\s*\)|\bdoc\(\s*[\w$.]+\s*,\s*["'`]([\w-]{1,100})["'`]/g;

function keyKind(key: string): SupabaseTarget["keyKind"] {
  if (key.startsWith("sb_publishable_")) return "publishable";
  if (key.startsWith("sb_secret_")) return "secret";
  const p = decodeJwtPayload(key);
  if (p?.role === "anon") return "anon-jwt";
  if (p?.role === "service_role") return "service-role";
  return "unknown";
}

function supabaseJwtRef(key: string): string | undefined {
  const p = decodeJwtPayload(key);
  if (!p || (p.iss !== "supabase" && typeof p.iss === "string" && !p.iss.includes("supabase"))) return undefined;
  return typeof p.ref === "string" ? p.ref : undefined;
}

function field(window: string, name: string): string | undefined {
  const re = new RegExp(`["']?${name}["']?\\s*:\\s*["'\`]([^"'\`]+)["'\`]`);
  return re.exec(window)?.[1];
}

export function detect(files: SourceFile[]): Detection {
  const det: Detection = {
    supabase: [],
    firebase: [],
    tables: new Set(),
    buckets: new Set(),
    rpcs: new Set(),
    collections: new Set(),
  };
  const sbByUrl = new Map<string, SupabaseConfig>();
  const urls: Array<{ url: string; file: string }> = [];
  const keys: Array<{ key: string; file: string }> = [];
  const addSupabase = (url: string, key: string, source: string) => {
    const clean = url.replace(/\/+$/, "");
    const kind = keyKind(key);
    if (kind === "unknown" && !key.startsWith("eyJ")) return;
    const existing = sbByUrl.get(clean);
    // Prefer the least-privileged key: that is what the browser really uses.
    if (existing && (existing.keyKind === "anon-jwt" || existing.keyKind === "publishable")) return;
    sbByUrl.set(clean, { url: clean, keyKind: kind, key: maskSecret(key), rawKey: key, source });
  };

  for (const f of files) {
    for (const m of f.content.matchAll(CREATE_CLIENT)) if (m[1] && m[2]) addSupabase(m[1], m[2], f.location);
  }
  const explicitKeys = new Set([...sbByUrl.values()].map((s) => s.rawKey));

  for (const f of files) {
    const c = f.content;
    for (const m of c.matchAll(SUPABASE_URL)) urls.push({ url: m[0], file: f.location });
    for (const m of c.matchAll(JWT)) {
      if (explicitKeys.has(m[0])) continue;
      const ref = supabaseJwtRef(m[0]);
      // Privileged keys are reported by the secret rules and never used for probing.
      if (ref && keyKind(m[0]) === "anon-jwt") addSupabase(`https://${ref}.supabase.co`, m[0], f.location);
    }
    for (const m of c.matchAll(PUBLISHABLE)) keys.push({ key: m[0], file: f.location });
    for (const m of c.matchAll(TABLE_REF)) if (m[1]) det.tables.add(m[1]);
    for (const m of c.matchAll(BUCKET_REF)) if (m[1]) det.buckets.add(m[1]);
    for (const m of c.matchAll(PUBLIC_BUCKET_URL)) if (m[1]) det.buckets.add(m[1]);
    for (const m of c.matchAll(RPC_REF)) if (m[1]) det.rpcs.add(m[1]);
    for (const m of c.matchAll(FS_COLLECTION)) {
      const name = m[1] ?? m[2] ?? m[3];
      if (name) det.collections.add(name);
    }

    for (const m of c.matchAll(/["']?apiKey["']?\s*:\s*["'`](AIza[0-9A-Za-z_-]{35})["'`]/g)) {
      const start = Math.max(0, (m.index ?? 0) - 800);
      const window = c.slice(start, (m.index ?? 0) + 1200);
      const projectId = field(window, "projectId");
      if (!projectId) continue;
      if (det.firebase.some((x) => x.projectId === projectId)) continue;
      det.firebase.push({
        apiKey: m[1],
        projectId,
        authDomain: field(window, "authDomain"),
        databaseURL: field(window, "databaseURL"),
        storageBucket: field(window, "storageBucket"),
        source: f.location,
      });
    }
  }

  for (const k of keys) {
    const sameFile = urls.find((u) => u.file === k.file) ?? urls[0];
    if (sameFile) addSupabase(sameFile.url, k.key, k.file);
  }
  det.supabase = [...sbByUrl.values()];
  return det;
}

export function publicSupabase(det: Detection): SupabaseTarget[] {
  return det.supabase.map(({ rawKey: _raw, ...rest }) => rest);
}

/** Runs the secret rules over every file. One finding per distinct secret. */
export function scanSecrets(files: SourceFile[]): Finding[] {
  const found = new Map<string, Finding & { count: number }>();
  for (const f of files) {
    for (const rule of SECRET_RULES) {
      rule.pattern.lastIndex = 0;
      for (const m of f.content.matchAll(rule.pattern)) {
        const value = m[rule.group ?? 0];
        if (!value) continue;
        const idx = m.index ?? 0;
        const context = f.content.slice(Math.max(0, idx - 400), idx + value.length + 400);
        if (rule.validate && !rule.validate(value, context)) continue;
        const key = `${rule.id}:${value}`;
        const prev = found.get(key);
        if (prev) {
          prev.count++;
          continue;
        }
        const fromMap = f.kind === "map-source";
        found.set(key, {
          ruleId: `secrets/${rule.id}`,
          severity: rule.severity,
          category: "secrets",
          title: `${rule.name} exposed in ${fromMap ? "source map" : f.kind === "html" || f.kind === "inline" ? "HTML" : "client bundle"}`,
          detail:
            (rule.note ? `${rule.note} ` : "") +
            "Anything shipped to the browser is public. Treat this secret as leaked: rotate it now, then move it to server-side code.",
          location: f.location,
          evidence: maskSecret(value),
          fix: secretFix(rule.id),
          links: rule.rotate ? [rule.rotate] : undefined,
          count: 1,
        });
      }
    }
  }
  return [...found.values()].map(({ count, ...finding }) =>
    count > 1 ? { ...finding, detail: `${finding.detail} (seen ${count} times)` } : finding,
  );
}

function secretFix(id: string): string {
  if (id.startsWith("supabase")) {
    return "1. Rotate the key in the Supabase dashboard (API Keys).\n2. Use only the `anon`/`sb_publishable_` key in the browser.\n3. Keep the service key in server code (Route Handlers, Server Actions, Edge Functions) and never prefix it with `NEXT_PUBLIC_` / `VITE_`.";
  }
  return "1. Revoke/rotate the key with the provider.\n2. Move the call that needs it to the server (API route, Server Action, Edge Function).\n3. Make sure the env var has no `NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_` or `REACT_APP_` prefix.";
}
