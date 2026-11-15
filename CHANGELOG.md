# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-16

### Added

- `npx leakboy <url | folder>` CLI with text, JSON, Markdown and SARIF output, `--fail-under`, `--only` and `--no-probe`.
- Crawler for Next.js, Vite, Nuxt, SvelteKit, Astro, Remix, CRA and Angular bundles, including lazy chunks and public
  and hidden source maps.
- 31 secret rules (Supabase, Stripe, OpenAI, Anthropic, Gemini, AWS, GitHub, Midtrans, Xendit, database URLs and more),
  with masked evidence.
- Read-only Supabase probe: exposed schema, tables readable by anon (row counts and column names only), listable
  storage buckets, instant sign-up.
- Read-only Firebase probe: Realtime Database, Firestore collections, Cloud Storage listing.
- Exposed file checks (`.env`, `.git`, `.npmrc`, SQL dumps, `docker-compose.yml`, `.DS_Store`) and security header
  checks, including reflected CORS with credentials.
- Explainable 0–100 score with A–F grades.
- Web app with SSRF protection, rate limiting, shareable reports and README badges.
- GitHub Action.
- Vulnerable/hardened lab app for tests and demos.
