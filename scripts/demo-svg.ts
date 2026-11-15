/**
 * Renders a real scan of the vulnerable lab as a terminal-style SVG for the README.
 * Lab hostnames are swapped for realistic ones; findings and masking are exactly what leakboy printed.
 *   npm run build:cli && node scripts/demo-svg.ts > docs/demo.svg
 */
import { startLab } from "../lab/server.ts";
import { scan, formatText } from "../packages/leakboy/dist/index.js";

const lab = await startLab({ vulnerable: true, port: 3000 });
const result = await scan(lab.url, { allowPrivateNetworks: true, endpoints: lab.endpoints });
await lab.close();

const text = formatText({ ...result, target: "https://my-vibe-app.vercel.app/", durationMs: 4200 }, { color: false })
  .replaceAll(`${lab.url}/sb`, "https://xyzcompanyrefabcde.supabase.co")
  .replaceAll(`${lab.url}/rtdb`, "https://my-vibe-app-default-rtdb.firebaseio.com")
  .replaceAll(lab.url, "https://my-vibe-app.vercel.app")
  .replaceAll("leakboy-lab", "my-vibe-app")
  .replace(/\d+ request\(s\)/, "62 request(s)")
  .split("\n")
  .filter((l) => !l.includes("Run with --verbose"));

const COLORS: Array<[RegExp, string]> = [
  [/✗ CRITICAL/, "#ff4d5e"],
  [/✗ HIGH/, "#ff7a45"],
  [/✗ MEDIUM/, "#f5c542"],
  [/✗ LOW/, "#4cc2ff"],
  [/Score \d+/, "#ff4d5e"],
  [/^\s+✓/, "#3ddc84"],
  [/^\s{13}/, "#7d8597"],
];
const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const lineH = 19;
const lines = ["$ npx leakboy https://my-vibe-app.vercel.app", ...text];
const width = 900;
const height = lines.length * lineH + 70;
const body = lines
  .map((l, i) => {
    const color = i === 0 ? "#e6e9ef" : (COLORS.find(([re]) => re.test(l))?.[1] ?? "#e6e9ef");
    const bold = /CRITICAL|Score|leakboy v/.test(l) ? ' font-weight="700"' : "";
    return `<text x="20" y="${58 + i * lineH}" fill="${color}"${bold} xml:space="preserve">${esc(l)}</text>`;
  })
  .join("\n");

process.stdout.write(`<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" font-size="13.5">
<rect width="${width}" height="${height}" rx="10" fill="#0b0d12"/>
<rect width="${width}" height="32" rx="10" fill="#161b26"/><rect y="22" width="${width}" height="10" fill="#161b26"/>
<circle cx="20" cy="16" r="6" fill="#ff5f57"/><circle cx="40" cy="16" r="6" fill="#febc2e"/><circle cx="60" cy="16" r="6" fill="#28c840"/>
${body}
</svg>
`);
