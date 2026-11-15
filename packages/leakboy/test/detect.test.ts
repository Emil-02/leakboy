import { describe, expect, it } from "vitest";
import { detect } from "../src/detect.js";
import { extractChunkRefs, extractScriptUrls, detectFrameworks } from "../src/crawler.js";

const anon = [
  Buffer.from('{"alg":"HS256"}').toString("base64url"),
  Buffer.from(JSON.stringify({ iss: "supabase", ref: "abcdefghijklmnopqrst", role: "anon" })).toString("base64url"),
  "s".repeat(43),
].join(".");

describe("detect", () => {
  it("finds Supabase from a JWT ref, plus tables, buckets and rpcs", () => {
    const det = detect([
      {
        location: "a.js",
        kind: "js",
        content: `x("${anon}");s.from("profiles").select();s.storage.from("avatars").list();s.rpc("add_credits",{})`,
      },
    ]);
    expect(det.supabase).toHaveLength(1);
    expect(det.supabase[0]?.url).toBe("https://abcdefghijklmnopqrst.supabase.co");
    expect(det.supabase[0]?.keyKind).toBe("anon-jwt");
    expect([...det.tables]).toEqual(["profiles"]);
    expect([...det.buckets]).toEqual(["avatars"]);
    expect([...det.rpcs]).toEqual(["add_credits"]);
  });

  it("prefers the createClient URL (custom domains) over the JWT ref", () => {
    const det = detect([{ location: "a.js", kind: "js", content: `createClient("https://db.myapp.com","${anon}")` }]);
    expect(det.supabase.map((s) => s.url)).toEqual(["https://db.myapp.com"]);
  });

  it("finds a Firebase config and Firestore collections", () => {
    const det = detect([
      {
        location: "a.js",
        kind: "js",
        content: `const c={apiKey:"AIza${"B".repeat(35)}",authDomain:"p.firebaseapp.com",projectId:"my-proj",storageBucket:"my-proj.appspot.com"};collection(db,"orders");db.collection("users")`,
      },
    ]);
    expect(det.firebase[0]?.projectId).toBe("my-proj");
    expect(det.firebase[0]?.storageBucket).toBe("my-proj.appspot.com");
    expect([...det.collections].sort()).toEqual(["orders", "users"]);
  });
});

describe("crawler helpers", () => {
  it("extracts scripts and modulepreload links", () => {
    const html = `<script src="/a.js"></script><link rel="modulepreload" href="/assets/b-123.js"><script>inline()</script>`;
    expect(extractScriptUrls(html, "https://x.dev/")).toEqual(["https://x.dev/a.js", "https://x.dev/assets/b-123.js"]);
  });

  it("resolves Next.js and Vite chunk references", () => {
    const refs = extractChunkRefs(`["static/chunks/app/page-1.js","./Login-abc.js","/_next/static/chunks/9.js"]`, "https://x.dev/assets/index.js", "https://x.dev");
    expect(refs).toContain("https://x.dev/_next/static/chunks/app/page-1.js");
    expect(refs).toContain("https://x.dev/assets/Login-abc.js");
    expect(refs).toContain("https://x.dev/_next/static/chunks/9.js");
  });

  it("detects frameworks", () => {
    expect(detectFrameworks(`<script src="/_next/static/chunks/main.js">`)).toEqual(["Next.js"]);
    expect(detectFrameworks(`<script type="module" crossorigin src="/assets/index-Ab12.js">`)).toEqual(["Vite"]);
  });
});
