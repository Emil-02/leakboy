# Contributing

Thanks for helping! Issues and PRs are welcome, in English or Bahasa Indonesia.

## Setup

```sh
git clone https://github.com/Emil-02/leakboy && cd leakboy
npm ci
npm run build:cli      # builds packages/leakboy
npm test               # unit + end-to-end tests against the lab
npm run typecheck
npm run lab            # vulnerable app on :4000, hardened app on :4001
npm run dev:web        # web UI on :3000 (set LEAKBOY_WEB_ALLOW_PRIVATE=1 to scan the lab)
```

## Layout

```
packages/leakboy/src/
  crawler.ts          download HTML, scripts, lazy chunks, source maps
  detect.ts           find Supabase/Firebase configs, table/bucket/collection names, run secret rules
  rules/secrets.ts    secret patterns  ← most contributions go here
  probes/             read-only checks: supabase.ts, firebase.ts, exposure.ts (files + headers)
  score.ts            scoring model
  report/             text, markdown, sarif
  http.ts             HTTP client with SSRF guard and budgets
apps/web/             Next.js site + /api/scan + /api/badge
lab/server.ts         fake vulnerable/hardened app used by tests and demos
```

## Adding a secret rule

1. Add an entry to `SECRET_RULES` in `packages/leakboy/src/rules/secrets.ts`:

   ```ts
   {
     id: "acme",
     name: "Acme API key",
     severity: "critical",
     pattern: /\bacme_live_[A-Za-z0-9]{32}\b/g,
     validate: random(4),            // optional: drop placeholders / low-entropy matches
     rotate: "https://acme.com/settings/keys",
   },
   ```

2. Add a test in `packages/leakboy/test/secrets.test.ts`. **Build fake keys at runtime** (`["acme", "live", rnd(32)].join("_")`)
   so that no secret-shaped string is committed and GitHub push protection stays quiet.
3. Prefer precise prefixes over generic regexes. False positives cost more trust than missed keys.

## Adding a probe

Probes must stay **read-only** and must **never output data values**: only counts, names and masked evidence. If you
add a probe, extend the lab (`lab/server.ts`) with a vulnerable and a hardened variant and add an e2e assertion.

## Commit style

Short imperative subject (`add Acme key rule`, `fix chunk discovery for Astro`). Update `CHANGELOG.md` for
user-visible changes.
