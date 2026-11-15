import { readdir, readFile, stat } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import { filesFromSourceMap, parseSourceMap, type SourceFile } from "./crawler.js";

const SKIP_DIRS = new Set(["node_modules", ".git", "cache", ".turbo", ".vercel", ".svelte-kit/output/server", "coverage"]);
const EXT = /\.(m?js|cjs|html?|json|map|txt|svg)$/i;
const MAX_FILE = 8 * 1024 * 1024;
const MAX_TOTAL = 300 * 1024 * 1024;

/** Folders whose contents are shipped to the browser. Source maps here will be public once deployed. */
const CLIENT_PATH = /(^|[/\\])(\.next[/\\]static|dist|build|out|public|_next|assets|static)([/\\]|$)/;
/** Next.js server output: never sent to the browser, so secrets there are expected. */
const SERVER_PATH = /(^|[/\\])\.next[/\\](server|standalone|types|trace)|(^|[/\\])\.output[/\\]server/;

export interface LocalScan {
  files: SourceFile[];
  clientSourceMaps: string[];
  skippedServerFiles: number;
}

export async function collectLocal(root: string): Promise<LocalScan> {
  const out: LocalScan = { files: [], clientSourceMaps: [], skippedServerFiles: 0 };
  let total = 0;

  async function walk(dir: string): Promise<void> {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const full = join(dir, e.name);
      const rel = relative(root, full) || e.name;
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name)) continue;
        await walk(full);
        continue;
      }
      if (!e.isFile() || !EXT.test(e.name)) continue;
      if (SERVER_PATH.test(rel)) {
        out.skippedServerFiles++;
        continue;
      }
      const info = await stat(full);
      if (info.size > MAX_FILE || total + info.size > MAX_TOTAL) continue;
      total += info.size;
      const content = await readFile(full, "utf8");
      const display = rel.split(sep).join("/");
      if (e.name.endsWith(".map")) {
        const map = parseSourceMap(content);
        if (map) {
          if (CLIENT_PATH.test(rel) || !rel.includes("/")) out.clientSourceMaps.push(display);
          out.files.push(...filesFromSourceMap(map, display));
          continue;
        }
      }
      out.files.push({
        location: display,
        content,
        kind: /\.html?$/i.test(e.name) ? "html" : /\.json$/i.test(e.name) ? "json" : /js$/i.test(e.name) ? "js" : "other",
      });
    }
  }

  await walk(root);
  return out;
}
