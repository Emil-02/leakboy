#!/usr/bin/env node
import { writeFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import pc from "picocolors";
import { formatMarkdown } from "./report/markdown.js";
import { formatSarif } from "./report/sarif.js";
import { formatText } from "./report/text.js";
import { scan } from "./scan.js";
import { CATEGORIES, type Category } from "./types.js";
import { VERSION } from "./version.js";

const HELP = `
  ${pc.bold("leakboy")} – find the leaks in your vibe-coded app before someone else does

  ${pc.bold("Usage")}
    npx leakboy <url | build-folder> [options]

  ${pc.bold("Examples")}
    npx leakboy https://myapp.vercel.app
    npx leakboy ./dist                       scan a build before deploying
    npx leakboy myapp.com --fail-under 80    exit 1 if the score is below 80 (CI)
    npx leakboy myapp.com --sarif leakboy.sarif --markdown report.md

  ${pc.bold("Options")}
    --json                 print the full result as JSON
    --sarif <file>         write SARIF 2.1.0 (GitHub code scanning)
    --markdown <file>      write a Markdown report (PR comments, issues)
    --fail-under <score>   exit with code 1 when the score is below this (0-100)
    --only <list>          comma list of: ${CATEGORIES.join(", ")}
    --no-probe             do not contact Supabase/Firebase, only read the bundle
    --timeout <ms>         per-request timeout (default 10000)
    --max-requests <n>     request budget (default 250)
    --verbose, -v          show details, fixes and request errors
    --no-color             disable colors
    --version, -V          print version
    --help, -h             show this help

  leakboy is passive and read-only: it never writes data, never prints row contents
  and masks every secret. Only scan apps you own or are allowed to test.
`;

async function main(): Promise<number> {
  let args;
  try {
    args = parseArgs({
      allowPositionals: true,
      options: {
        json: { type: "boolean" },
        sarif: { type: "string" },
        markdown: { type: "string" },
        "fail-under": { type: "string" },
        only: { type: "string" },
        "no-probe": { type: "boolean" },
        timeout: { type: "string" },
        "max-requests": { type: "string" },
        verbose: { type: "boolean", short: "v" },
        "no-color": { type: "boolean" },
        version: { type: "boolean", short: "V" },
        help: { type: "boolean", short: "h" },
      },
    });
  } catch (err) {
    process.stderr.write(`${pc.red("error")} ${(err as Error).message}\n${HELP}`);
    return 2;
  }
  const { values, positionals } = args;
  if (values.version) {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  if (values.help || positionals.length === 0) {
    process.stdout.write(HELP);
    return positionals.length === 0 && !values.help ? 2 : 0;
  }

  const color = !values["no-color"] && !process.env.NO_COLOR && process.stdout.isTTY === true;
  const only = values.only
    ?.split(",")
    .map((s) => s.trim())
    .filter(Boolean) as Category[] | undefined;
  const bad = only?.filter((o) => !CATEGORIES.includes(o));
  if (bad?.length) {
    process.stderr.write(`${pc.red("error")} unknown category: ${bad.join(", ")} (use ${CATEGORIES.join(", ")})\n`);
    return 2;
  }
  const failUnder = values["fail-under"] !== undefined ? Number(values["fail-under"]) : undefined;
  if (failUnder !== undefined && (!Number.isFinite(failUnder) || failUnder < 0 || failUnder > 100)) {
    process.stderr.write(`${pc.red("error")} --fail-under must be a number between 0 and 100\n`);
    return 2;
  }

  const showProgress = !values.json && process.stderr.isTTY === true;
  const target = positionals[0] as string;
  let result;
  try {
    result = await scan(target, {
      only,
      noProbe: values["no-probe"],
      allowPrivateNetworks: true,
      timeoutMs: values.timeout ? Number(values.timeout) : undefined,
      maxRequests: values["max-requests"] ? Number(values["max-requests"]) : undefined,
      endpoints: {
        ...(process.env.LEAKBOY_FIRESTORE_ENDPOINT ? { firestore: process.env.LEAKBOY_FIRESTORE_ENDPOINT } : {}),
        ...(process.env.LEAKBOY_FIREBASE_STORAGE_ENDPOINT ? { firebaseStorage: process.env.LEAKBOY_FIREBASE_STORAGE_ENDPOINT } : {}),
      },
      onProgress: showProgress ? (m) => process.stderr.write(`\r\x1b[2K${pc.dim(`  ${m}…`)}`) : undefined,
    });
  } catch (err) {
    if (showProgress) process.stderr.write("\r\x1b[2K");
    process.stderr.write(`${pc.red("error")} ${(err as Error).message}\n`);
    return 2;
  }
  if (showProgress) process.stderr.write("\r\x1b[2K");

  if (values.json) process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  else process.stdout.write(formatText(result, { color, verbose: values.verbose }));

  if (values.sarif) await writeFile(values.sarif, `${JSON.stringify(formatSarif(result), null, 2)}\n`);
  if (values.markdown) await writeFile(values.markdown, formatMarkdown(result));

  if (failUnder !== undefined && result.score.score < failUnder) {
    if (!values.json) process.stderr.write(pc.red(`  Score ${result.score.score} is below --fail-under ${failUnder}\n`));
    return 1;
  }
  return 0;
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    process.stderr.write(`${pc.red("error")} ${(err as Error).stack ?? err}\n`);
    process.exitCode = 2;
  },
);
