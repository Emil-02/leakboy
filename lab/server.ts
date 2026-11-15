/**
 * leakboy lab: a fake "vibe-coded" app plus fake Supabase and Firebase backends.
 *
 *   npm run lab            # vulnerable app on :4000, hardened app on :4001
 *   npx leakboy http://localhost:4000
 *
 * Everything is in-memory and every "secret" is random and generated at startup,
 * so nothing real is ever exposed (and GitHub push protection stays quiet).
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";

export interface Lab {
  url: string;
  port: number;
  /** Pass to `scan(..., { endpoints })` so Firebase calls hit the lab instead of Google. */
  endpoints: { firestore: string; firebaseStorage: string };
  secrets: Record<string, string>;
  close(): Promise<void>;
}

const rand = (n: number, alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") =>
  Array.from(randomBytes(n), (b) => alphabet[b % alphabet.length]).join("");

const b64url = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");

function jwt(role: string): string {
  const payload = { iss: "supabase", ref: "leakboylab0000000000", role, iat: 1700000000, exp: 2000000000 };
  return `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url(payload)}.${randomBytes(32).toString("base64url")}`;
}

function makeSecrets() {
  return {
    anon: jwt("anon"),
    serviceRole: jwt("service_role"),
    stripe: ["sk", "live", rand(32)].join("_"),
    openai: ["sk", "proj", rand(64, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")].join("-"),
    firebaseApiKey: `AIza${rand(35)}`,
  };
}

function send(res: ServerResponse, status: number, body: string | object, headers: Record<string, string> = {}) {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  const type = typeof body === "string" ? "text/plain; charset=utf-8" : "application/json";
  res.writeHead(status, { "content-type": type, ...headers });
  res.end(text);
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => resolve(data));
  });
}

export async function startLab(opts: { vulnerable: boolean; port?: number }): Promise<Lab> {
  const v = opts.vulnerable;
  const s = makeSecrets();
  let base = "";

  const html = () => `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Lab App ${v ? "(vulnerable)" : "(hardened)"}</title>
<script src="/_next/static/chunks/main-app.js" async></script>
<script src="https://www.googletagmanager.com/gtag/js?id=G-LAB"></script>
</head><body><div id="__next">Lab app</div>
<script>self.__next_f=self.__next_f||[];self.__next_f.push([1,"1:I[\\"static/chunks/app/page-7f3a.js\\"]"])</script>
</body></html>`;

  const mainApp = () => `"use strict";
const supabase = createClient("${base}/sb", "${s.anon}");
const firebaseConfig = {apiKey:"${s.firebaseApiKey}",authDomain:"leakboy-lab.firebaseapp.com",projectId:"leakboy-lab",databaseURL:"${base}/rtdb",storageBucket:"leakboy-lab.appspot.com"};
async function load(){ await supabase.from("profiles").select("*"); await supabase.from("products").select("*"); await supabase.from("private_notes").select("*"); await supabase.storage.from("avatars").list(); return collection(db, "orders"); }
${v ? "//# sourceMappingURL=main-app.js.map" : ""}`;

  const pageChunk = () =>
    v
      ? `"use strict";const stripe = "${s.stripe}"; fetch("https://api.openai.com/v1/chat/completions",{headers:{authorization:"Bearer ${s.openai}"}});`
      : `"use strict";fetch("/api/checkout",{method:"POST"});`;

  const sourceMap = () =>
    JSON.stringify({
      version: 3,
      file: "main-app.js",
      mappings: "AAAA",
      sources: ["webpack://lab/./src/lib/admin.ts", "webpack://lab/./node_modules/react/index.js"],
      sourcesContent: [`export const SUPABASE_SERVICE_ROLE = "${s.serviceRole}";\n`, "module.exports = {}"],
    });

  const secureHeaders: Record<string, string> = v
    ? {}
    : {
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
      };

  const handler = async (req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? "/", base);
    const p = url.pathname;
    const origin = req.headers.origin;
    const cors: Record<string, string> =
      v && origin ? { "access-control-allow-origin": origin, "access-control-allow-credentials": "true" } : {};

    // --- the web app ---
    if (p === "/") return send(res, 200, html(), { "content-type": "text/html; charset=utf-8", ...secureHeaders, ...cors });
    if (p === "/_next/static/chunks/main-app.js") return send(res, 200, mainApp(), { "content-type": "application/javascript" });
    if (p === "/_next/static/chunks/app/page-7f3a.js") return send(res, 200, pageChunk(), { "content-type": "application/javascript" });
    if (v && p === "/_next/static/chunks/main-app.js.map") return send(res, 200, sourceMap(), { "content-type": "application/json" });
    if (v && p === "/.env") return send(res, 200, `NEXT_PUBLIC_SUPABASE_URL=${base}/sb\nSUPABASE_SERVICE_ROLE_KEY=${s.serviceRole}\nSTRIPE_SECRET_KEY=${s.stripe}\n`);
    if (v && p === "/.git/config") return send(res, 200, "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://github.com/lab/app.git\n");

    // --- fake Supabase ---
    if (p.startsWith("/sb/")) {
      const key = req.headers.apikey;
      if (key !== s.anon) return send(res, 401, { message: "Invalid API key" });
      if (p === "/sb/rest/v1/") {
        if (!v) return send(res, 401, { message: "schema not exposed" });
        return send(res, 200, {
          swagger: "2.0",
          paths: { "/": {}, "/profiles": {}, "/products": {}, "/private_notes": {}, "/rpc/add_credits": {} },
          definitions: {
            profiles: { properties: { id: {}, email: {}, full_name: {}, phone: {} } },
            products: { properties: { id: {}, name: {}, price: {} } },
            private_notes: { properties: { id: {}, user_id: {}, body: {} } },
          },
        });
      }
      const table = /^\/sb\/rest\/v1\/([\w]+)$/.exec(p)?.[1];
      if (table) {
        if (!["profiles", "products", "private_notes"].includes(table)) {
          return send(res, 404, { code: "PGRST205", message: `Could not find the table 'public.${table}'` });
        }
        if (!v || table === "private_notes") return send(res, 200, [], { "content-range": "*/0" });
        if (table === "profiles") return send(res, 200, [{ id: 1, email: "lab@example.com", full_name: "Lab User", phone: "000" }], { "content-range": "0-0/1240" });
        return send(res, 200, [{ id: 1, name: "Coffee", price: 1 }], { "content-range": "0-0/12" });
      }
      if (p === "/sb/storage/v1/bucket") return send(res, 200, []);
      if (p.startsWith("/sb/storage/v1/object/list/") && req.method === "POST") {
        await readBody(req);
        return send(res, 200, v ? [{ name: "ktp-scan.jpg" }] : []);
      }
      if (p === "/sb/auth/v1/settings") return send(res, 200, { disable_signup: false, mailer_autoconfirm: v });
      return send(res, 404, { message: "not found" });
    }

    // --- fake Firebase ---
    if (p === "/rtdb/.json") return v ? send(res, 200, { users: true, orders: true }) : send(res, 401, { error: "Permission denied" });
    if (p.startsWith("/firestore/v1/projects/leakboy-lab/databases/(default)/documents/")) {
      if (!v) return send(res, 403, { error: { code: 403, status: "PERMISSION_DENIED" } });
      const coll = decodeURIComponent(p.split("/").pop() ?? "");
      return send(res, 200, coll === "orders" ? { documents: [{ name: "x" }] } : {});
    }
    if (p.startsWith("/fbstorage/v0/b/")) {
      return v ? send(res, 200, { items: [{ name: "uploads/invoice.pdf" }] }) : send(res, 403, { error: { code: 403 } });
    }

    // SPA fallback: unknown paths return the HTML page with 200, like many hosts do.
    return send(res, 200, html(), { "content-type": "text/html; charset=utf-8" });
  };

  const server: Server = createServer((req, res) => {
    handler(req, res).catch((err) => send(res, 500, String(err)));
  });
  await new Promise<void>((resolve) => server.listen(opts.port ?? 0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  base = `http://127.0.0.1:${port}`;
  return {
    url: base,
    port,
    endpoints: { firestore: `${base}/firestore`, firebaseStorage: `${base}/fbstorage` },
    secrets: s,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const vuln = await startLab({ vulnerable: true, port: Number(process.env.LAB_PORT ?? 4000) });
  const safe = await startLab({ vulnerable: false, port: Number(process.env.LAB_SAFE_PORT ?? 4001) });
  console.log(`leakboy lab
  vulnerable app: ${vuln.url}
  hardened app:   ${safe.url}

Try:
  LEAKBOY_FIRESTORE_ENDPOINT=${vuln.endpoints.firestore} \\
  LEAKBOY_FIREBASE_STORAGE_ENDPOINT=${vuln.endpoints.firebaseStorage} \\
  npx leakboy ${vuln.url}

  npx leakboy ${safe.url}`);
}
