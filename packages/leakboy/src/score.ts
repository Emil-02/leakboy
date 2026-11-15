import type { Finding, Score, ScoreItem, Severity } from "./types.js";

export const SEVERITY_POINTS: Record<Severity, number> = {
  critical: 40,
  high: 20,
  medium: 8,
  low: 3,
  info: 0,
};

export const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/**
 * 100 minus a fixed number of points per finding. Any critical finding caps the score at 49 (grade F),
 * because a single readable users table is a breach no matter how good the headers are.
 */
export function computeScore(findings: Finding[]): Score {
  const deductions: ScoreItem[] = findings
    .filter((f) => SEVERITY_POINTS[f.severity] > 0)
    .map((f) => ({ ruleId: f.ruleId, title: f.title, severity: f.severity, points: SEVERITY_POINTS[f.severity] }))
    .sort((a, b) => b.points - a.points);
  let score = Math.max(0, 100 - deductions.reduce((s, d) => s + d.points, 0));
  const capped = findings.some((f) => f.severity === "critical") && score > 49;
  if (capped) score = 49;
  return { score, grade: gradeFor(score), deductions, capped };
}

export function gradeFor(score: number): Score["grade"] {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 65) return "C";
  if (score >= 50) return "D";
  return "F";
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || a.category.localeCompare(b.category) || a.title.localeCompare(b.title),
  );
}
