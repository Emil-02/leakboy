import { describe, expect, it } from "vitest";
import { scanSecrets } from "../src/detect.js";
import { entropy, maskSecret } from "../src/rules/secrets.js";
import type { SourceFile } from "../src/crawler.js";

// Fake keys are assembled at runtime so no secret-shaped string lives in the repo.
const rnd = (n: number) => Array.from({ length: n }, (_, i) => "aZ3kP9qR7tX2mW8vB4nL6yC1"[(i * 7 + n) % 24]).join("");
const jwt = (role: string) =>
  [
    Buffer.from('{"alg":"HS256","typ":"JWT"}').toString("base64url"),
    Buffer.from(JSON.stringify({ iss: "supabase", ref: "abcdefghijklmnopqrst", role })).toString("base64url"),
    "x".repeat(10) + rnd(33),
  ].join(".");

const file = (content: string, kind: SourceFile["kind"] = "js"): SourceFile => ({ location: "https://app.test/main.js", content, kind });

describe("secret rules", () => {
  it("flags a Supabase service_role JWT but not the anon key", () => {
    const findings = scanSecrets([file(`a="${jwt("service_role")}";b="${jwt("anon")}"`)]);
    expect(findings.map((f) => f.ruleId)).toEqual(["secrets/supabase-service-role"]);
    expect(findings[0]?.severity).toBe("critical");
  });

  it("flags Stripe live keys and masks them", () => {
    const key = ["sk", "live", rnd(30)].join("_");
    const [f] = scanSecrets([file(`const k="${key}"`)]);
    expect(f?.ruleId).toBe("secrets/stripe-secret-live");
    expect(f?.evidence).not.toContain(key.slice(10, 26));
    expect(f?.evidence).toMatch(/•/);
  });

  it("ignores placeholders", () => {
    expect(scanSecrets([file(`k="${["sk", "live", "xxxxxxxxxxxxxxxxxxxxxxxxxxxx"].join("_")}"`)])).toHaveLength(0);
    expect(scanSecrets([file("postgres://user:password@localhost:5432/db")])).toHaveLength(0);
  });

  it("only flags a Google API key when it is used for Gemini", () => {
    const key = `AIza${rnd(35)}`;
    expect(scanSecrets([file(`firebase({apiKey:"${key}",projectId:"p"})`)])).toHaveLength(0);
    const hits = scanSecrets([file(`fetch("https://generativelanguage.googleapis.com/v1beta?key=${key}")`)]);
    expect(hits[0]?.ruleId).toBe("secrets/google-ai");
  });

  it("flags database URLs with real passwords", () => {
    const [f] = scanSecrets([file(`DATABASE_URL="postgresql://app:${rnd(20)}@db.example.com:5432/prod"`)]);
    expect(f?.ruleId).toBe("secrets/database-url");
  });

  it("dedupes the same secret across files", () => {
    const key = ["sk", "live", rnd(30)].join("_");
    const findings = scanSecrets([file(key), { ...file(key), location: "other.js" }]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.detail).toContain("seen 2 times");
  });

  it("entropy and masking helpers behave", () => {
    expect(entropy("aaaaaaaa")).toBe(0);
    expect(entropy(rnd(40))).toBeGreaterThan(3.5);
    expect(maskSecret("short")).toBe("sh••••••");
  });
});
