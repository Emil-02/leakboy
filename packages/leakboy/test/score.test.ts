import { describe, expect, it } from "vitest";
import { computeScore } from "../src/score.js";
import type { Finding } from "../src/types.js";

const f = (severity: Finding["severity"]): Finding => ({ ruleId: `x/${severity}`, severity, category: "headers", title: severity, detail: "" });

describe("score", () => {
  it("is 100/A with no findings", () => {
    expect(computeScore([])).toMatchObject({ score: 100, grade: "A", capped: false });
  });
  it("deducts per severity", () => {
    expect(computeScore([f("low"), f("low"), f("medium")]).score).toBe(86);
    expect(computeScore([f("high")]).grade).toBe("B");
  });
  it("any critical finding means F", () => {
    expect(computeScore([f("critical")])).toMatchObject({ score: 49, grade: "F", capped: true });
  });
  it("never goes below 0", () => {
    expect(computeScore(Array(5).fill(f("critical"))).score).toBe(0);
  });
});
