# Ethics & acceptable use

leakboy exists so builders can find their own mistakes before attackers do.

## Rules

1. **Only scan apps you own, or apps whose owner has given you permission** (for example through a bug bounty
   program whose scope includes them).
2. **Do not use findings to access data.** leakboy proves a table is readable by counting rows. Downloading the rows
   yourself goes beyond testing, and in many countries it is a crime.
3. **Report responsibly.** If you stumble on someone else's leak, contact the owner privately (`security.txt`, a
   security@ address, or the platform's bug bounty) and give them time to fix it before saying anything publicly.
   Never publish table names, URLs or keys of an unfixed app.
4. **Aggregate research must be anonymised.** "X % of N apps had an open table" is fine. Naming apps is not, unless
   they have been fixed and the owner agreed.

## What leakboy does to stay safe

- Only reads. The one `POST` it sends is Supabase Storage's `object/list`, which is read-only.
- Never signs up, inserts, updates, deletes or calls RPC functions.
- Never uses privileged keys it finds (`service_role`, `sb_secret_`).
- Never prints row contents or full secrets. This is covered by the test suite.
- Uses a request/byte/time budget per scan and identifies itself with the
  `leakboy/<version> (+https://github.com/Emil-02/leakboy)` User-Agent, so site owners can see the traffic in their logs.

If you run a site and want leakboy's hosted scanner to stop scanning it, open an issue or email the maintainer.
