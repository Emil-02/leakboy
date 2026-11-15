import type { Detection } from "../detect.js";
import type { Endpoints, FirebaseTarget } from "../types.js";
import { SENSITIVE_NAME, type ProbeContext } from "./supabase.js";

export const COMMON_COLLECTIONS = [
  "users", "profiles", "accounts", "customers", "orders", "payments", "transactions", "messages",
  "chats", "posts", "comments", "products", "bookings", "notifications", "contacts", "leads",
  "feedback", "settings", "admins", "documents", "invoices", "subscriptions",
];

const FIRESTORE_RULES_FIX = [
  "Lock Firestore down and grant access per document owner:",
  "",
  "```",
  "rules_version = '2';",
  "service cloud.firestore {",
  "  match /databases/{database}/documents {",
  "    match /users/{userId}/{document=**} {",
  "      allow read, write: if request.auth != null && request.auth.uid == userId;",
  "    }",
  "    // everything else is closed by default",
  "  }",
  "}",
  "```",
].join("\n");

const RTDB_RULES_FIX = [
  "Replace open rules with per-user rules:",
  "",
  "```json",
  "{",
  '  "rules": {',
  '    ".read": false,',
  '    ".write": false,',
  '    "users": {',
  '      "$uid": { ".read": "auth.uid === $uid", ".write": "auth.uid === $uid" }',
  "    }",
  "  }",
  "}",
  "```",
].join("\n");

export async function probeFirebase(
  cfg: FirebaseTarget,
  det: Detection,
  endpoints: Endpoints,
  ctx: ProbeContext,
): Promise<void> {
  const { http } = ctx;
  const pid = cfg.projectId;
  if (!pid) return;
  ctx.onProgress?.(`Probing Firebase project ${pid}`);

  // Realtime Database
  const dbUrls = new Set<string>();
  if (cfg.databaseURL) dbUrls.add(cfg.databaseURL.replace(/\/+$/, ""));
  else dbUrls.add(`https://${pid}-default-rtdb.firebaseio.com`);
  let rtdbStatus: "pass" | "fail" | "skip" = "skip";
  for (const db of dbUrls) {
    try {
      const res = await http.request(`${db}/.json?shallow=true`, { maxBytes: 256 * 1024 });
      if (res.status === 401 || res.status === 403) {
        rtdbStatus = "pass";
        continue;
      }
      if (res.status !== 200) continue;
      const data = res.json<unknown>();
      if (data === null || data === undefined) {
        rtdbStatus = rtdbStatus === "fail" ? "fail" : "pass";
        continue;
      }
      rtdbStatus = "fail";
      const keys = typeof data === "object" ? Object.keys(data as object).length : 1;
      ctx.findings.push({
        ruleId: "firebase/rtdb-readable",
        severity: "critical",
        category: "firebase",
        title: `Realtime Database is readable by anyone (${keys} top-level node(s))`,
        detail:
          "The database root answers without authentication, so anyone can download the whole database with one request. Your rules probably contain `\".read\": true`.",
        location: `${db}/.json`,
        fix: RTDB_RULES_FIX,
        links: ["https://firebase.google.com/docs/database/security"],
      });
    } catch (err) {
      ctx.errors.push(`firebase rtdb: ${(err as Error).message}`);
    }
  }
  ctx.checks.push({ id: "firebase/rtdb", category: "firebase", title: "Realtime Database locked", status: rtdbStatus });

  // Firestore
  if (cfg.apiKey) {
    const collections = [...new Set([...det.collections, ...COMMON_COLLECTIONS])].slice(0, 40);
    let readable = 0;
    let denied = 0;
    for (const coll of collections) {
      if (http.remainingRequests <= 3) break;
      try {
        const url =
          `${endpoints.firestore}/v1/projects/${encodeURIComponent(pid)}/databases/(default)/documents/` +
          `${encodeURIComponent(coll)}?pageSize=1&key=${encodeURIComponent(cfg.apiKey)}`;
        const res = await http.request(url, { maxBytes: 256 * 1024 });
        if (res.status === 403 || res.status === 401) {
          denied++;
          continue;
        }
        if (res.status === 404) break; // Firestore not enabled for this project
        if (res.status !== 200) continue;
        const body = res.json<{ documents?: unknown[] }>();
        if (!body?.documents?.length) continue;
        readable++;
        ctx.findings.push({
          ruleId: "firebase/firestore-readable",
          severity: SENSITIVE_NAME.test(coll) ? "critical" : "high",
          category: "firebase",
          title: `Firestore collection "${coll}" is readable by anyone`,
          detail:
            "Using only the public web API key, leakboy could read documents from this collection. Your Firestore rules allow unauthenticated reads (for example `allow read: if true` or test-mode rules).",
          location: `firestore://${pid}/${coll}`,
          fix: FIRESTORE_RULES_FIX,
          links: ["https://firebase.google.com/docs/firestore/security/get-started"],
        });
      } catch (err) {
        ctx.errors.push(`firestore ${coll}: ${(err as Error).message}`);
        if ((err as Error).name === "BudgetExceededError") break;
      }
    }
    ctx.checks.push({
      id: "firebase/firestore",
      category: "firebase",
      title: "Firestore locked",
      status: readable ? "fail" : denied ? "pass" : "skip",
      note: `${readable + denied} collection(s) answered, ${readable} readable.`,
    });
  }

  // Cloud Storage for Firebase
  const buckets = new Set<string>();
  if (cfg.storageBucket) buckets.add(cfg.storageBucket);
  else {
    buckets.add(`${pid}.appspot.com`);
    buckets.add(`${pid}.firebasestorage.app`);
  }
  let storageStatus: "pass" | "fail" | "skip" = "skip";
  for (const bucket of buckets) {
    try {
      const res = await http.request(`${endpoints.firebaseStorage}/v0/b/${encodeURIComponent(bucket)}/o?maxResults=1`, {
        maxBytes: 64 * 1024,
      });
      if (res.status === 403 || res.status === 401) {
        storageStatus = storageStatus === "fail" ? "fail" : "pass";
        continue;
      }
      if (res.status !== 200) continue;
      const body = res.json<{ items?: unknown[]; prefixes?: unknown[] }>();
      if (!body?.items?.length && !body?.prefixes?.length) {
        storageStatus = storageStatus === "fail" ? "fail" : "pass";
        continue;
      }
      storageStatus = "fail";
      ctx.findings.push({
        ruleId: "firebase/storage-listable",
        severity: "high",
        category: "firebase",
        title: `Firebase Storage bucket "${bucket}" can be listed by anyone`,
        detail: "Anyone can enumerate and download every uploaded file. Your Storage rules allow unauthenticated reads.",
        location: `gs://${bucket}`,
        fix: [
          "```",
          "rules_version = '2';",
          "service firebase.storage {",
          "  match /b/{bucket}/o {",
          "    match /users/{userId}/{allPaths=**} {",
          "      allow read, write: if request.auth != null && request.auth.uid == userId;",
          "    }",
          "  }",
          "}",
          "```",
        ].join("\n"),
        links: ["https://firebase.google.com/docs/storage/security"],
      });
    } catch (err) {
      ctx.errors.push(`firebase storage: ${(err as Error).message}`);
    }
  }
  ctx.checks.push({ id: "firebase/storage", category: "firebase", title: "Firebase Storage locked", status: storageStatus });
}
