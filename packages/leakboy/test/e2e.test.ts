import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { startLab, type Lab } from "../../../lab/server.js";
import { scan, formatSarif, formatMarkdown, formatText } from "../src/index.js";

const run = promisify(execFile);
let vuln: Lab;
let safe: Lab;

beforeAll(async () => {
  vuln = await startLab({ vulnerable: true });
  safe = await startLab({ vulnerable: false });
});
afterAll(async () => {
  await vuln.close();
  await safe.close();
});

describe("vulnerable lab", () => {
  it("finds every planted leak and gets an F", async () => {
    const result = await scan(vuln.url, { allowPrivateNetworks: true, endpoints: vuln.endpoints });
    const ids = result.findings.map((f) => f.ruleId);
    expect(result.score.grade).toBe("F");
    expect(ids).toEqual(
      expect.arrayContaining([
        "secrets/supabase-service-role",
        "secrets/stripe-secret-live",
        "secrets/openai",
        "secrets/source-maps",
        "supabase/table-readable",
        "supabase/bucket-files-listable",
        "supabase/instant-signup",
        "firebase/rtdb-readable",
        "firebase/firestore-readable",
        "firebase/storage-listable",
        "exposure/env-file",
        "exposure/git",
        "headers/cors",
        "headers/csp",
      ]),
    );
    const profiles = result.findings.find((f) => f.title.includes('"profiles"'));
    expect(profiles?.severity).toBe("critical");
    expect(profiles?.title).toContain("1,240");
    expect(profiles?.detail).toContain("`email`");
    const products = result.findings.find((f) => f.title.includes('"products"'));
    expect(products?.severity).toBe("low");
    expect(result.findings.some((f) => f.title.includes("private_notes"))).toBe(false);
    expect(result.detected.frameworks).toContain("Next.js");
    expect(result.detected.supabase.map((s) => s.url)).toEqual([`${vuln.url}/sb`]);
  });

  it("never leaks secret values or row data into any output", async () => {
    const result = await scan(vuln.url, { allowPrivateNetworks: true, endpoints: vuln.endpoints });
    const outputs = [JSON.stringify(result), JSON.stringify(formatSarif(result)), formatMarkdown(result), formatText(result, { verbose: true })];
    for (const out of outputs) {
      for (const secret of Object.values(vuln.secrets)) {
        if (secret.startsWith("AIza")) continue; // Firebase web keys are public by design and are masked anyway
        expect(out).not.toContain(secret);
        expect(out).not.toContain(secret.slice(12, 40));
      }
      expect(out).not.toContain("lab@example.com");
      expect(out).not.toContain("ktp-scan.jpg");
    }
  });

  it("respects --only", async () => {
    const result = await scan(vuln.url, { allowPrivateNetworks: true, only: ["headers"] });
    expect(new Set(result.findings.map((f) => f.category))).toEqual(new Set(["headers"]));
  });

  it("refuses to scan the lab when private networks are not allowed", async () => {
    await expect(scan(vuln.url)).rejects.toThrow(/private/);
  });
});

describe("hardened lab", () => {
  it("gets a clean A", async () => {
    const result = await scan(safe.url, { allowPrivateNetworks: true, endpoints: safe.endpoints });
    expect(result.findings).toEqual([]);
    expect(result.score).toMatchObject({ score: 100, grade: "A" });
    expect(result.checks.find((c) => c.id === "supabase/rls")?.status).toBe("pass");
    expect(result.checks.find((c) => c.id === "firebase/firestore")?.status).toBe("pass");
  });
});

describe("local build scan", () => {
  it("finds secrets and client source maps in a build folder, ignoring server output", async () => {
    const dir = await mkdtemp(join(tmpdir(), "leakboy-"));
    try {
      await mkdir(join(dir, ".next/static/chunks"), { recursive: true });
      await mkdir(join(dir, ".next/server"), { recursive: true });
      await writeFile(join(dir, ".next/static/chunks/main.js"), `const k="${vuln.secrets.stripe}";`);
      await writeFile(join(dir, ".next/static/chunks/main.js.map"), JSON.stringify({ version: 3, mappings: "A", sources: ["src/a.ts"], sourcesContent: ["x"] }));
      await writeFile(join(dir, ".next/server/route.js"), `const k="${vuln.secrets.openai}";`);
      await mkdir(join(dir, ".next/dev/static/chunks"), { recursive: true });
      await writeFile(join(dir, ".next/dev/static/chunks/dev.js.map"), JSON.stringify({ version: 3, mappings: "A", sources: ["d.ts"], sourcesContent: ["y"] }));
      const result = await scan(dir, { noProbe: true });
      expect(result.mode).toBe("local");
      // Pointing at .next itself must classify server/dev output the same way.
      const inner = await scan(join(dir, ".next"), { noProbe: true });
      expect(inner.findings.map((f) => f.ruleId).sort()).toEqual(["secrets/source-maps", "secrets/stripe-secret-live"]);
      expect(inner.findings.find((f) => f.ruleId === "secrets/source-maps")?.title).toMatch(/^1 source map/);
      const ids = result.findings.map((f) => f.ruleId);
      expect(ids).toContain("secrets/stripe-secret-live");
      expect(ids).toContain("secrets/source-maps");
      expect(ids).not.toContain("secrets/openai");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("cli", () => {
  const cli = join(import.meta.dirname, "../dist/cli.js");
  it("exits 1 below --fail-under and writes SARIF/markdown", async () => {
    const dir = await mkdtemp(join(tmpdir(), "leakboy-cli-"));
    try {
      const env = { ...process.env, LEAKBOY_FIRESTORE_ENDPOINT: vuln.endpoints.firestore, LEAKBOY_FIREBASE_STORAGE_ENDPOINT: vuln.endpoints.firebaseStorage };
      const err = await run("node", [cli, vuln.url, "--fail-under", "80", "--sarif", join(dir, "r.sarif"), "--markdown", join(dir, "r.md")], { env }).catch((e) => e);
      expect(err.code).toBe(1);
      expect(err.stdout).toContain("grade F");
      const ok = await run("node", [cli, safe.url, "--json", "--fail-under", "90"]);
      expect(JSON.parse(ok.stdout).score.grade).toBe("A");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("blocked targets", () => {
  it.each([
    [403, { "x-vercel-mitigated": "challenge" }, "<title>Vercel Security Checkpoint</title>", /Vercel Security Checkpoint/],
    [403, { "cf-mitigated": "challenge" }, "<title>Just a moment...</title>", /Cloudflare/],
    [500, {}, "oops", /HTTP 500/],
  ])("refuses to score a %s challenge/error page", async (status, headers, body, reason) => {
    const { createServer } = await import("node:http");
    const server = createServer((_req, res) => {
      res.writeHead(status, { "content-type": "text/html", ...headers });
      res.end(body);
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as { port: number }).port;
    try {
      const err = await scan(`http://127.0.0.1:${port}/`, { allowPrivateNetworks: true }).catch((e) => e);
      expect(err.name).toBe("TargetBlockedError");
      expect(err.message).toMatch(reason);
      expect(err.message).toMatch(/cannot give a score/);
    } finally {
      server.close();
    }
  });
});
