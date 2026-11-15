# Security policy

## Reporting a vulnerability in leakboy

Please **do not open a public issue**. Use GitHub's private vulnerability reporting instead:
[Report a vulnerability](https://github.com/Emil-02/leakboy/security/advisories/new).

Please include steps to reproduce and the version (`npx leakboy --version`). You will get an answer within 7 days.

Of particular interest:

- Ways to make the hosted scanner (`apps/web`) reach private or internal addresses (SSRF), including redirects,
  DNS rebinding, IPv6 and odd IP encodings.
- Any path where a secret value or row content ends up unmasked in leakboy's output.
- Any request leakboy makes that could change data on the target.

## Supported versions

Only the latest release gets security fixes.
