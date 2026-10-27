# Upstream

This directory is a copy of the Cloudflare agent skills repository, placed under the `cloudflare` vendor namespace, plus two files added in this fork (`UPSTREAM.md` and `REVIEW-waypost.md`).

| Field | Value |
| --- | --- |
| Source | https://github.com/cloudflare/skills |
| Branch | `main` (default branch HEAD at copy time) |
| Commit | `86505e44f87d801aa1864a3c4109e9a8ae5c409f` |
| Upstream commit time | 2026-10-15T14:19:27-07:00 |
| Subject | Merge pull request #241 from sybeeria/fix-workers-profiling-cf-link |
| Date copied | 2026-10-27 |
| License | Apache License 2.0 (`LICENSE` in this directory) |

The upstream `.git` directory was excluded. File contents from that commit are unchanged, including `LICENSE`, `README.md`, `rules/`, and the nested `.github` workflows. GitHub only runs workflows in the repository root `.github/workflows`, so those nested workflow files do not run in Waypost.

Layout: upstream's repository root sits at `.agents/skills/cloudflare/`. Each bundle that upstream keeps in `skills/<name>/` is placed at `.agents/skills/cloudflare/<name>/` (for example `workers-best-practices/SKILL.md` and `cloudflare/references/d1/`). Relative links inside upstream files were not rewritten. `rules/workers.mdc` still points at `../skills/...`, which is the upstream layout.

Skill bundles copied (19 `SKILL.md` files):

- `agents-sdk`
- `basin`
- `cf-cli`
- `cloudflare`
- `cloudflare-email-service`
- `cloudflare-one`
- `cloudflare-one-migrations`
- `durable-objects`
- `gateway-workers`
- `k2`
- `nextjs-on-cloudflare`
- `sandbox-migrate-to-next`
- `sandbox-next`
- `sandbox-stable`
- `turnstile-spin`
- `web-perf`
- `workers-best-practices`
- `workers-profiling`
- `wrangler`
