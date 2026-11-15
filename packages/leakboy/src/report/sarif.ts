import type { ScanResult, Severity } from "../types.js";

const LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.5",
  low: "3.0",
  info: "0.0",
};

/** SARIF 2.1.0 for GitHub code scanning. URLs become logical locations since they are not repo files. */
export function formatSarif(result: ScanResult): object {
  const rules = new Map<string, { id: string; name: string; shortDescription: { text: string }; properties: object }>();
  for (const f of result.findings) {
    if (!rules.has(f.ruleId)) {
      rules.set(f.ruleId, {
        id: f.ruleId,
        name: f.ruleId.replace(/[^\w]+/g, "_"),
        shortDescription: { text: f.title },
        properties: { tags: ["security", f.category], "security-severity": SECURITY_SEVERITY[f.severity] },
      });
    }
  }
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "leakboy",
            version: result.tool.version,
            informationUri: "https://github.com/Emil-02/leakboy",
            rules: [...rules.values()],
          },
        },
        results: result.findings.map((f) => {
          const isFile = result.mode === "local" && f.location && !/^https?:/.test(f.location);
          return {
            ruleId: f.ruleId,
            level: LEVEL[f.severity],
            message: { text: `${f.title}. ${f.detail}${f.evidence ? ` Evidence: ${f.evidence}` : ""}` },
            locations: [
              isFile
                ? { physicalLocation: { artifactLocation: { uri: f.location?.split(" -> ")[0] }, region: { startLine: 1 } } }
                : {
                    physicalLocation: { artifactLocation: { uri: f.location ?? result.target }, region: { startLine: 1 } },
                    logicalLocations: [{ fullyQualifiedName: f.location ?? result.target, kind: "resource" }],
                  },
            ],
            partialFingerprints: { leakboy: `${f.ruleId}:${f.location ?? ""}:${f.evidence ?? ""}` },
          };
        }),
      },
    ],
  };
}
