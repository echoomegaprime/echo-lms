# Security policy

Echo LMS is a multi-tenant Cloudflare Worker (Hono, D1 + KV) holding student PII (names,
emails), course/revenue data, and Stripe payment metadata for every tenant.

## Fixed in this consolidation pass

1. **The auth middleware exempted every GET request unconditionally, not just the intended
   public ones.** The repo already has a deliberate `/public/*` prefix for its storefront
   surface (a hand-picked, field-filtered JSON/HTML view of one course) -- but the blanket
   `c.req.method === 'GET'` exemption meant every OTHER GET route was reachable with zero
   credentials too, given only a guessable id:
   - `/tenants/:id`, `/students`, `/students/:sid/enrollments` -- names and emails;
   - `/analytics/overview`, `/analytics/student-activity` -- per-tenant revenue estimates
     and student activity;
   - `/courses/slug/:slug` -- the raw, unfiltered course row (unlike `/public/course/:id`,
     which deliberately picks a safe subset of fields);
   - `/quizzes/:qid/attempts`, `/courses/:cid/enrollments`, and every other management read.

   Narrowed the exemption to the routes actually meant to be public: `/`, `/health`,
   `/status`, `/public/*`, `/webhooks/stripe` (has its own HMAC signature check), and
   `/certificates/verify/:num` (a legitimate public certificate-verification page, the
   equivalent of a "verify my diploma" link).
2. **Timing side-channel in the credential check.** `checkAuth`-equivalent logic compared the
   submitted key with `key !== c.env.ECHO_API_KEY`. Replaced with a constant-time
   `timingSafeEqual`. (The Stripe webhook's own HMAC verification in `verifyStripeSignature`
   was already constant-time -- an XOR-accumulator loop -- and was left unchanged.)

## Known, not fixed: npm audit findings are all dev-tooling transitives

`npm audit` reports 8 vulnerabilities (undici, ws) via `wrangler`/`miniflare`'s dependency
tree -- these are local dev-server/build tooling, never shipped in the deployed Worker bundle.
Fixing them (`npm audit fix --force`) bumps `wrangler` 3.60 -> 4.120, a major version with
breaking changes to the config/build pipeline that was not verified against a live
deployment in this pass. Same disposition as the identical finding on `echo-compliance-auditor`
earlier in this consolidation campaign.

## Supported version

Security fixes target the current `main` branch. Historical commits are retained for evidence
and are not patched in place.

## Report a vulnerability

Do not open a public issue for a suspected vulnerability. Send a private report to
`security@echo-op.com` with:

- affected endpoint and exact revision;
- reproduction steps and expected impact (this service holds student PII and Stripe payment
  metadata across every tenant -- treat any auth-boundary issue as high severity);
- safe contact details for follow-up.

Never include a live `ECHO_API_KEY`, `STRIPE_SECRET_KEY`, or `STRIPE_WEBHOOK_SECRET` in a
report.
