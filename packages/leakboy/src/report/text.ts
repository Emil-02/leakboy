import pc from "picocolors";
import type { Finding, ScanResult, Severity } from "../types.js";

type Colors = ReturnType<typeof pc.createColors>;

const LABEL: Record<Severity, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO",
};

function sevColor(c: Colors, s: Severity): (t: string) => string {
  switch (s) {
    case "critical":
      return (t) => c.bold(c.red(t));
    case "high":
      return c.red;
    case "medium":
      return c.yellow;
    case "low":
      return c.cyan;
    default:
      return c.dim;
  }
}

function gradeColor(c: Colors, grade: string): (t: string) => string {
  if (grade === "A") return (t) => c.bold(c.green(t));
  if (grade === "B") return c.green;
  if (grade === "C") return c.yellow;
  if (grade === "D") return (t) => c.bold(c.yellow(t));
  return (t) => c.bold(c.red(t));
}

function indent(text: string, pad: string): string {
  return text
    .split("\n")
    .map((l) => pad + l)
    .join("\n");
}

export interface TextOptions {
  color?: boolean;
  verbose?: boolean;
}

export function formatText(result: ScanResult, opts: TextOptions = {}): string {
  const c = pc.createColors(opts.color ?? true);
  const lines: string[] = [];
  const { score, grade } = result.score;
  const g = gradeColor(c, grade);
  lines.push("");
  lines.push(`  ${c.bold("leakboy")} ${c.dim(`v${result.tool.version}`)}  ${c.dim("→")}  ${result.target}`);
  const meta = [
    result.detected.frameworks.join(", "),
    result.detected.supabase.length ? `Supabase ×${result.detected.supabase.length}` : "",
    result.detected.firebase.length ? `Firebase ×${result.detected.firebase.length}` : "",
    `${result.stats.scripts} script(s)`,
    result.mode === "url" ? `${result.stats.requests} request(s)` : "local build",
    `${(result.durationMs / 1000).toFixed(1)}s`,
  ].filter(Boolean);
  lines.push(`  ${c.dim(meta.join(" · "))}`);
  lines.push("");
  lines.push(`  ${g(`Score ${score}/100`)}  ${g(`grade ${grade}`)}${result.score.capped ? c.dim("  (capped: critical issue found)") : ""}`);
  lines.push("");

  const shown = result.findings.filter((f) => opts.verbose || f.severity !== "info");
  if (!shown.length) {
    lines.push(`  ${c.green("✓")} No leaks found.`);
  }
  for (const f of shown) lines.push(...findingLines(c, f, opts.verbose ?? false));

  const passed = result.checks.filter((k) => k.status === "pass");
  if (passed.length) {
    lines.push("");
    let row = "";
    let rowLen = 0;
    for (const k of passed) {
      const plain = `✓ ${k.title}`;
      if (rowLen && rowLen + plain.length + 3 > 96) {
        lines.push(`  ${row}`);
        row = "";
        rowLen = 0;
      }
      row += `${rowLen ? c.dim("  ·  ") : ""}${c.green("✓")} ${k.title}`;
      rowLen += plain.length + (rowLen ? 5 : 0);
    }
    if (row) lines.push(`  ${row}`);
  }
  if (opts.verbose && result.errors.length) {
    lines.push("");
    lines.push(c.dim(`  ${result.errors.length} request error(s):`));
    result.errors.slice(0, 20).forEach((e) => lines.push(c.dim(`    - ${e}`)));
  }
  if (shown.some((f) => f.fix) && !opts.verbose) {
    lines.push("");
    lines.push(c.dim("  Run with --verbose for fixes, or --markdown report.md for a shareable report."));
  }
  lines.push("");
  return lines.join("\n");
}

function findingLines(c: Colors, f: Finding, verbose: boolean): string[] {
  const color = sevColor(c, f.severity);
  const out = [`  ${color("✗ " + LABEL[f.severity].padEnd(8))} ${f.title}`];
  const pad = "             ";
  if (f.location) out.push(c.dim(`${pad}${f.location}`));
  if (f.evidence) out.push(c.dim(`${pad}${f.evidence}`));
  if (verbose) {
    out.push(indent(f.detail, pad));
    if (f.fix) out.push(c.dim(indent(f.fix, pad)));
    f.links?.forEach((l) => out.push(c.dim(`${pad}↳ ${l}`)));
    out.push("");
  }
  return out;
}
