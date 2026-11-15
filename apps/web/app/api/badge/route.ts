import { badgeSvg } from "@/lib/badge";
import { clientIp, parseTarget, rateLimit, scanCached } from "@/lib/server-scan";

export const runtime = "nodejs";
export const maxDuration = 60;
export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  let svg: string;
  let ok = true;
  try {
    const target = parseTarget(new URL(req.url).searchParams.get("url"));
    if (!rateLimit(clientIp(req))) throw new Error("rate limited");
    const result = await scanCached(target);
    svg = badgeSvg(result.score.grade, result.score.score);
  } catch {
    ok = false;
    svg = badgeSvg("?");
  }
  return new Response(svg, {
    headers: {
      "content-type": "image/svg+xml; charset=utf-8",
      "cache-control": ok ? "public, max-age=3600, s-maxage=21600, stale-while-revalidate=86400" : "no-store",
    },
  });
}
