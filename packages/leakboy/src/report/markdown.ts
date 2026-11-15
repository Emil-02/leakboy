import type { ScanResult, Severity } from "../types.js";

const ICON: Record<Severity, string> = {
  critical: "🔴 Critical",
  high: "🟠 High",
  medium: "🟡 Medium",
  low: "🔵 Low",
  info: "⚪ Info",
};

const esc = (s: string) => s.replace(/\|/g, "\\|").replace(/\n/g, " ");

export function formatMarkdown(result: ScanResult): string {
  const { score, grade } = result.score;
  const out: string[] = [];
  out.push(`## 🤠 leakboy: ${grade} (${score}/100)`);
  out.push("");
  out.push(`Target: \`${result.target}\` · ${result.findings.length} finding(s) · ${result.stats.requests} request(s) · leakboy v${result.tool.version}`);
  out.push("");
  if (!result.findings.length) {
    out.push("✅ No leaks found.");
  } else {
    out.push("| Severity | Finding | Where |");
    out.push("|---|---|---|");
    for (const f of result.findings) {
      out.push(`| ${ICON[f.severity]} | ${esc(f.title)} | ${f.location ? `\`${esc(f.location)}\`` : ""} |`);
    }
    out.push("");
    for (const f of result.findings.filter((x) => x.severity !== "info")) {
      out.push(`<details><summary><b>${ICON[f.severity]}</b> ${esc(f.title)}</summary>`);
      out.push("");
      out.push(f.detail);
      if (f.evidence) out.push(`\nEvidence (masked): \`${f.evidence}\``);
      if (f.fix) out.push(`\n**Fix**\n\n${f.fix}`);
      if (f.links?.length) out.push(`\n${f.links.map((l) => `- ${l}`).join("\n")}`);
      out.push("\n</details>\n");
    }
  }
  const passed = result.checks.filter((c) => c.status === "pass");
  if (passed.length) out.push(`\nPassed: ${passed.map((c) => `✅ ${c.title}`).join(" · ")}`);
  out.push("");
  return out.join("\n");
}
