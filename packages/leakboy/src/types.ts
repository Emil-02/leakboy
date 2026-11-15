export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Category = "secrets" | "supabase" | "firebase" | "exposure" | "headers";

export const CATEGORIES: readonly Category[] = ["secrets", "supabase", "firebase", "exposure", "headers"];

export const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

export interface Finding {
  /** Stable rule identifier, e.g. `supabase/table-readable`. */
  ruleId: string;
  severity: Severity;
  category: Category;
  title: string;
  /** Human explanation. Never contains secret values or row data. */
  detail: string;
  /** Where it was found: a URL, file path or table name. */
  location?: string;
  /** Masked evidence, safe to print and share. */
  evidence?: string;
  /** How to fix it (markdown). */
  fix?: string;
  /** Links with more info, e.g. key rotation pages. */
  links?: string[];
}

export interface Check {
  id: string;
  category: Category;
  title: string;
  status: "pass" | "fail" | "skip";
  note?: string;
}

export interface SupabaseTarget {
  url: string;
  keyKind: "anon-jwt" | "publishable" | "service-role" | "secret" | "unknown";
  /** Masked key for display. */
  key: string;
  source?: string;
}

export interface FirebaseTarget {
  projectId?: string;
  apiKey?: string;
  databaseURL?: string;
  storageBucket?: string;
  authDomain?: string;
  source?: string;
}

export interface ScanStats {
  requests: number;
  scripts: number;
  sourceMaps: number;
  bytes: number;
}

export interface ScoreItem {
  ruleId: string;
  title: string;
  severity: Severity;
  points: number;
}

export interface Score {
  score: number;
  grade: "A" | "B" | "C" | "D" | "F";
  deductions: ScoreItem[];
  /** True when a critical finding capped the score. */
  capped: boolean;
}

export interface ScanResult {
  tool: { name: "leakboy"; version: string };
  target: string;
  mode: "url" | "local";
  startedAt: string;
  durationMs: number;
  score: Score;
  findings: Finding[];
  checks: Check[];
  detected: {
    supabase: SupabaseTarget[];
    firebase: FirebaseTarget[];
    frameworks: string[];
  };
  stats: ScanStats;
  errors: string[];
}

export interface ScanOptions {
  /** Restrict to some categories. Default: all. */
  only?: Category[];
  /** Allow scanning localhost / private networks. The CLI allows it, the web demo never does. */
  allowPrivateNetworks?: boolean;
  /** Only allow ports 80/443 (web demo). */
  standardPortsOnly?: boolean;
  /** Per-request timeout in ms. */
  timeoutMs?: number;
  /** Total request budget for one scan. */
  maxRequests?: number;
  /** Max bytes downloaded for a single response. */
  maxResponseBytes?: number;
  /** Max total bytes downloaded for one scan. */
  maxTotalBytes?: number;
  /** Stop starting new requests after this many ms (partial results are still returned). */
  maxDurationMs?: number;
  /** Max JS files to fetch. */
  maxScripts?: number;
  /** Skip probing backends (Supabase/Firebase) and only report what is in the bundle. */
  noProbe?: boolean;
  onProgress?: (message: string) => void;
  /** Test hooks: override fixed Google endpoints. */
  endpoints?: Partial<Endpoints>;
}

export interface Endpoints {
  firestore: string;
  firebaseStorage: string;
}

export const DEFAULT_ENDPOINTS: Endpoints = {
  firestore: "https://firestore.googleapis.com",
  firebaseStorage: "https://firebasestorage.googleapis.com",
};
