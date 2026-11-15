import { readdir, readFile, stat } from "node:fs/promises";
import { basename, join, relative, sep } from "node:path";
import { filesFromSourceMap, parseSourceMap, type SourceFile } from "./crawler.js";

const SKIP_DIRS = new Set(["node_modules", ".git", ".turbo", ".vercel", "coverage"]);
const EXT = /\.(m?js|cjs|html?|json|map|txt|svg)$/i;
const MAX_FILE = 8 * 1024 * 1024;
const MAX_TOTAL = 300 * 1024 * 1024;

/** Folders whose contents are shipped to the browser. Source maps here will be public once deployed. */
const CLIENT_PATH = /(^|[/\\])(\.next[/\\]static|dist|build|out|public|_next|assets|static)([/\\]|$)/;
/**
 * Output that is never sent to the browser: Next.js server bundles, `next dev` output, Nuxt/Nitro server.
 * Secrets there are expected, and source maps there are not public.
 */
const NOT_SHIPPED = /(^|\/)\.next\/(server|standalone|types|trace|dev|cache)(\/|$)|(^|\/)\.output\/server(\/|$)|(^|\/)\.svelte-kit\/output\/server(\/|$)/;

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
      // Anchor on the scanned folder's own name so `leakboy .next` and `leakboy .` classify paths the same way.
      const anchored = `${basename(root)}/${rel.split(sep).join("/")}`;
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name)) continue;
        if (NOT_SHIPPED.test(anchored)) {
          out.skippedServerFiles++;
          continue;
        }
        await walk(full);
        continue;
      }
      if (!e.isFile() || !EXT.test(e.name)) continue;
      const info = await stat(full);
      if (info.size > MAX_FILE || total + info.size > MAX_TOTAL) continue;
      total += info.size;
      const content = await readFile(full, "utf8");
      const display = rel.split(sep).join("/");
      if (e.name.endsWith(".map")) {
        const map = parseSourceMap(content);
        if (map) {
          if (CLIENT_PATH.test(anchored)) out.clientSourceMaps.push(display);
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
