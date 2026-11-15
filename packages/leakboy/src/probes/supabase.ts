import type { HttpClient } from "../http.js";
import type { SupabaseConfig, Detection } from "../detect.js";
import type { Check, Finding, Severity } from "../types.js";

/** Table names that usually hold personal or business-critical data. */
export const SENSITIVE_NAME =
  /user|profile|account|customer|client|member|employee|staff|admin|order|payment|transaction|invoice|billing|subscription|wallet|balance|message|chat|conversation|inbox|email|contact|(^|_)leads?$|address|booking|reservation|patient|medical|health|student|tenant|secret|token|api_?keys?|credential|session|(^|_)logs?$|audit|kyc|ktp|identity|document|salary|payroll|ticket|application|private|receipt/i;

/** Table names that are usually meant to be public. */
const PUBLIC_NAME =
  /^(products?|posts?|articles?|blogs?|categor(y|ies)|tags?|pages?|faqs?|testimonials?|menus?|menu_items|services|galler(y|ies)|portfolio|projects|events|announcements|banners|countries|cities|provinces|regions|currencies|plans|pricing|features|changelog|news|courses|lessons|reviews|public_\w+)$/i;

/** Column names that point to personal data. Only names are reported, never values. */
const SENSITIVE_COLUMN =
  /e?mail|phone|whatsapp|wa_number|password|passwd|hash|token|secret|api_?key|address|birth|dob|nik|ktp|npwp|passport|ssn|salary|iban|card|cvv|bank|account_number|ip_address|lat(itude)?$|lng|longitude|location/i;

export const COMMON_TABLES = [
  "users", "profiles", "accounts", "customers", "orders", "payments", "transactions", "invoices",
  "subscriptions", "messages", "chats", "conversations", "notifications", "bookings", "reservations",
  "contacts", "leads", "waitlist", "feedback", "documents", "files", "uploads", "notes", "todos",
  "tasks", "posts", "comments", "products", "carts", "admins", "members", "organizations", "teams",
  "tenants", "employees", "students", "api_keys", "settings", "logs", "audit_logs", "wallets",
];

interface OpenApi {
  paths?: Record<string, unknown>;
  definitions?: Record<string, { properties?: Record<string, unknown> }>;
}

export interface ProbeContext {
  http: HttpClient;
  findings: Finding[];
  checks: Check[];
  errors: string[];
  onProgress?: (message: string) => void;
}

function headersFor(cfg: SupabaseConfig, extra: Record<string, string> = {}): Record<string, string> {
  const h: Record<string, string> = { apikey: cfg.rawKey, accept: "application/json", ...extra };
  if (cfg.rawKey.startsWith("eyJ")) h.authorization = `Bearer ${cfg.rawKey}`;
  return h;
}

export function rlsFix(table: string, columns: string[]): string {
  const owner = columns.find((c) => /^(user_id|owner_id|profile_id|created_by|author_id|uid)$/.test(c)) ?? "user_id";
  const idCol = table === "profiles" || table === "users" ? (columns.includes("id") ? "id" : owner) : owner;
  return [
    "Enable Row Level Security and only let people read their own rows:",
    "",
    "```sql",
    `alter table public.${table} enable row level security;`,
    "",
    `create policy "${table}: owner can read"`,
    `  on public.${table} for select`,
    "  to authenticated",
    `  using ((select auth.uid()) = ${idCol});`,
    "```",
    "",
    "If the table really is public, keep the policy but expose only safe columns through a view, and never grant `anon` access to personal data.",
  ].join("\n");
}

function classify(table: string, sensitiveCols: string[]): Severity {
  if (sensitiveCols.length || SENSITIVE_NAME.test(table)) return "critical";
  if (PUBLIC_NAME.test(table)) return "low";
  return "high";
}

export async function probeSupabase(cfg: SupabaseConfig, det: Detection, ctx: ProbeContext): Promise<void> {
  const { http } = ctx;
  const base = cfg.url;
  if (cfg.keyKind === "service-role" || cfg.keyKind === "secret") {
    ctx.checks.push({
      id: "supabase/probe",
      category: "supabase",
      title: `Supabase ${base}`,
      status: "skip",
      note: "Only a privileged key was found; leakboy never uses privileged keys.",
    });
    return;
  }
  ctx.onProgress?.(`Probing Supabase ${base}`);

  let schema: OpenApi | undefined;
  try {
    const res = await http.request(`${base}/rest/v1/`, { headers: headersFor(cfg, { accept: "application/openapi+json, application/json" }) });
    if (res.status === 200) schema = res.json<OpenApi>();
  } catch (err) {
    ctx.errors.push(`supabase schema: ${(err as Error).message}`);
  }

  const columnsOf = (t: string) => Object.keys(schema?.definitions?.[t]?.properties ?? {});
  const fromSchema = Object.keys(schema?.paths ?? {})
    .filter((p) => p !== "/" && !p.startsWith("/rpc/"))
    .map((p) => p.slice(1));
  const rpcs = Object.keys(schema?.paths ?? {}).filter((p) => p.startsWith("/rpc/"));
  const tables = new Set<string>([...fromSchema, ...det.tables]);
  const guessed = !schema;
  if (guessed) COMMON_TABLES.forEach((t) => tables.add(t));
  const list = [...tables].slice(0, 60);

  ctx.checks.push({
    id: "supabase/schema",
    category: "supabase",
    title: "API schema hidden from anon",
    status: schema ? "fail" : "pass",
    note: schema
      ? `${fromSchema.length} table(s)/view(s) and ${rpcs.length} RPC function(s) are listed publicly at /rest/v1/. This is normal for Supabase, but it tells attackers exactly what to try.`
      : "Schema not public; probing tables referenced in the bundle plus common names.",
  });

  let readable = 0;
  let probed = 0;
  for (const table of list) {
    if (http.remainingRequests <= 3) break;
    try {
      const res = await http.request(`${base}/rest/v1/${encodeURIComponent(table)}?select=*&limit=1`, {
        headers: headersFor(cfg, { prefer: "count=estimated", "range-unit": "items" }),
        maxBytes: 256 * 1024,
      });
      if (res.status === 404 || res.status === 400) continue;
      probed++;
      if (res.status !== 200 && res.status !== 206) continue;
      const rows = res.json<unknown[]>();
      // The row is only counted, never stored or printed.
      const hasRows = Array.isArray(rows) && rows.length > 0;
      if (!hasRows) continue;
      readable++;
      const total = /\/(\d+)$/.exec(res.headers.get("content-range") ?? "")?.[1];
      const cols = columnsOf(table).length ? columnsOf(table) : Object.keys((rows[0] ?? {}) as object);
      const sensitiveCols = cols.filter((c) => SENSITIVE_COLUMN.test(c));
      const severity = classify(table, sensitiveCols);
      const countText = total ? `≈${Number(total).toLocaleString("en-US")} row(s)` : "at least 1 row";
      ctx.findings.push({
        ruleId: "supabase/table-readable",
        severity,
        category: "supabase",
        title: `Table "${table}" is readable by anyone (${countText})`,
        detail:
          `Using only the public key from your bundle, leakboy could read rows from \`${table}\`` +
          (sensitiveCols.length ? `, including columns ${sensitiveCols.map((c) => `\`${c}\``).join(", ")}.` : ".") +
          (severity === "low"
            ? " The name suggests public content; check this is intended and that no private columns are exposed."
            : " Row Level Security is off or a policy allows `anon`/`public` to select everything."),
        location: `${base}/rest/v1/${table}`,
        fix: rlsFix(table, cols),
        links: ["https://supabase.com/docs/guides/database/postgres/row-level-security"],
      });
    } catch (err) {
      ctx.errors.push(`supabase table ${table}: ${(err as Error).message}`);
      if ((err as Error).name === "BudgetExceededError") break;
    }
  }
  ctx.checks.push({
    id: "supabase/rls",
    category: "supabase",
    title: "Tables protected by RLS",
    status: readable ? "fail" : probed ? "pass" : "skip",
    note: `${probed} table(s) checked as anon${guessed ? " (names partly guessed)" : ""}, ${readable} readable.`,
  });

  await probeStorage(cfg, det, ctx);
  await probeAuthSettings(cfg, ctx);
}

async function probeStorage(cfg: SupabaseConfig, det: Detection, ctx: ProbeContext): Promise<void> {
  const { http } = ctx;
  const buckets = new Set(det.buckets);
  try {
    const res = await http.request(`${cfg.url}/storage/v1/bucket`, { headers: headersFor(cfg) });
    const list = res.status === 200 ? res.json<Array<{ name?: string; id?: string }>>() : undefined;
    if (Array.isArray(list) && list.length) {
      list.forEach((b) => (b.name ?? b.id) && buckets.add((b.name ?? b.id) as string));
      ctx.findings.push({
        ruleId: "supabase/buckets-listable",
        severity: "low",
        category: "supabase",
        title: `Storage bucket list is public (${list.length} bucket(s))`,
        detail: "Anyone can list your storage buckets. On its own that is not a leak, but it reveals what to look for.",
        location: `${cfg.url}/storage/v1/bucket`,
        fix: "Remove `select` policies on `storage.buckets` for the `anon` role unless you need them.",
      });
    }
  } catch (err) {
    ctx.errors.push(`supabase buckets: ${(err as Error).message}`);
  }

  let listable = 0;
  for (const bucket of [...buckets].slice(0, 15)) {
    if (http.remainingRequests <= 3) break;
    try {
      // `list` is a POST in the Storage API, but it is read-only: it only returns object names.
      const res = await http.request(`${cfg.url}/storage/v1/object/list/${encodeURIComponent(bucket)}`, {
        method: "POST",
        headers: headersFor(cfg, { "content-type": "application/json" }),
        body: JSON.stringify({ prefix: "", limit: 1, offset: 0 }),
        maxBytes: 64 * 1024,
      });
      const items = res.status === 200 ? res.json<unknown[]>() : undefined;
      if (!Array.isArray(items) || !items.length) continue;
      listable++;
      ctx.findings.push({
        ruleId: "supabase/bucket-files-listable",
        severity: SENSITIVE_NAME.test(bucket) ? "critical" : "high",
        category: "supabase",
        title: `Files in storage bucket "${bucket}" can be listed by anyone`,
        detail:
          "Anyone can enumerate every file name in this bucket, and with a public bucket download them all. User uploads (IDs, invoices, photos) often end up here.",
        location: `${cfg.url}/storage/v1/object/list/${bucket}`,
        fix: [
          "Restrict `select` on `storage.objects` to the owner's folder:",
          "",
          "```sql",
          `create policy "${bucket}: owner can list"`,
          "  on storage.objects for select to authenticated",
          `  using (bucket_id = '${bucket}' and (storage.foldername(name))[1] = (select auth.uid())::text);`,
          "```",
        ].join("\n"),
        links: ["https://supabase.com/docs/guides/storage/security/access-control"],
      });
    } catch (err) {
      ctx.errors.push(`supabase bucket ${bucket}: ${(err as Error).message}`);
    }
  }
  ctx.checks.push({
    id: "supabase/storage",
    category: "supabase",
    title: "Storage not listable",
    status: listable ? "fail" : buckets.size ? "pass" : "skip",
    note: buckets.size ? `${buckets.size} bucket(s) checked, ${listable} listable.` : "No buckets referenced.",
  });
}

async function probeAuthSettings(cfg: SupabaseConfig, ctx: ProbeContext): Promise<void> {
  try {
    const res = await ctx.http.request(`${cfg.url}/auth/v1/settings`, { headers: headersFor(cfg) });
    const s = res.status === 200 ? res.json<{ disable_signup?: boolean; mailer_autoconfirm?: boolean }>() : undefined;
    if (!s) return;
    const instant = s.disable_signup === false && s.mailer_autoconfirm === true;
    ctx.checks.push({
      id: "supabase/auth-signup",
      category: "supabase",
      title: "Sign-up needs email confirmation",
      status: instant ? "fail" : "pass",
      note: s.disable_signup ? "Sign-ups are disabled." : undefined,
    });
    if (instant) {
      ctx.findings.push({
        ruleId: "supabase/instant-signup",
        severity: "medium",
        category: "supabase",
        title: "Anyone can create a confirmed account instantly",
        detail:
          "Sign-ups are open and emails are auto-confirmed, so the `authenticated` role is one API call away for anyone. Policies like `to authenticated using (true)` are effectively public.",
        location: `${cfg.url}/auth/v1/settings`,
        fix: "Turn on **Confirm email** (Authentication → Providers → Email) or disable sign-ups, and make sure policies check ownership (`auth.uid() = user_id`), not just `authenticated`.",
        links: ["https://supabase.com/docs/guides/auth/general-configuration"],
      });
    }
  } catch (err) {
    ctx.errors.push(`supabase auth settings: ${(err as Error).message}`);
  }
}
