# Echo LMS

Multi-tenant learning management system on Cloudflare Workers (Hono, D1 + KV). Courses,
modules, lessons, quizzes, enrollments, progress tracking, certificates, reviews,
discussions, per-tenant analytics, Stripe checkout for paid courses, and AI-assisted
outline/quiz generation via the fleet's engine runtime.

## Endpoints

| Access | Method | Path | Description |
|---|---|---|---|
| Public | GET | `/`, `/health`, `/status` | Service info / health |
| Public | GET/POST | `/public/course/:id`, `/public/course/:id/enroll` | Storefront course page + Stripe checkout redirect |
| Public | POST | `/webhooks/stripe` | Stripe webhook (own HMAC signature check) |
| Public | GET | `/certificates/verify/:num` | Public certificate verification |
| Authenticated | GET/POST/PUT/DELETE | everything else | Tenants, instructors, courses, modules, lessons, quizzes, students, enrollments, progress, certificates, reviews, discussions, analytics, AI generation |

## Authentication

All routes other than the public ones listed above require `X-Echo-API-Key`, compared to
`env.ECHO_API_KEY` in constant time. See [SECURITY.md](SECURITY.md) for what changed in this
consolidation pass -- the repo as found exempted every GET request from auth, not just the
intended public ones, which exposed student PII and revenue analytics to anyone who could
guess an id.

## Verify

```powershell
npm install
npm test
```

## Security

This service holds student PII (names, emails), course revenue data, and Stripe payment
metadata. See [SECURITY.md](SECURITY.md) to report a vulnerability -- never as a public issue.

## License

See [LICENSE](LICENSE). Contributions: see [CONTRIBUTING.md](CONTRIBUTING.md).
