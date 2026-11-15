import { NextResponse } from "next/server";
import { clientIp, parseTarget, rateLimit, scanCached, UserError, RATE_LIMIT } from "@/lib/server-scan";

export const runtime = "nodejs";
export const maxDuration = 60;
export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  try {
    const target = parseTarget(new URL(req.url).searchParams.get("url"));
    if (!rateLimit(clientIp(req))) {
      throw new UserError(`Slow down: at most ${RATE_LIMIT.max} scans per minute.`, 429);
    }
    const result = await scanCached(target);
    return NextResponse.json(result, {
      headers: { "cache-control": "public, s-maxage=600, stale-while-revalidate=3600" },
    });
  } catch (err) {
    const status = err instanceof UserError ? err.status : /private|local|only ports|only http|credentials/.test((err as Error).message) ? 400 : 502;
    return NextResponse.json({ error: (err as Error).message }, { status, headers: { "cache-control": "no-store" } });
  }
}
