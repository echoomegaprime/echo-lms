# Changelog

## Unreleased -- consolidation pass (2026-08-11)

### Fixed
- The auth middleware exempted every GET request unconditionally -- narrowed to the actual
  public routes (`/`, `/health`, `/status`, `/public/*`, `/webhooks/stripe`,
  `/certificates/verify/:num`). Previously any GET to `/tenants/:id`, `/students`,
  `/analytics/overview`, `/courses/slug/:slug`, etc. required no credential at all.
- Constant-time `timingSafeEqual` for the `X-Echo-API-Key` comparison (was raw `!==`).

### Added
- `tests/auth.test.mjs` -- 9 tests covering the narrowed public-path exemption (positive and
  negative), the management-API key gate, and a same-length-vs-different-length wrong-key
  timing-shape check.
- Full governance set (README, SECURITY, CONTRIBUTING, CODE_OF_CONDUCT, LICENSE, CI).

### Documented, not fixed
- `npm audit`'s 8 findings are all `wrangler`/`miniflare` dev-tooling transitives (undici,
  ws), never shipped in the deployed bundle; fixing requires an unverified major `wrangler`
  bump. See SECURITY.md.

## 2.0.0 -- original release

Multi-tenant LMS: courses/modules/lessons/quizzes, enrollments and progress tracking,
certificates, reviews, discussions, per-tenant analytics, Stripe checkout for paid courses,
AI-assisted outline/quiz generation.
