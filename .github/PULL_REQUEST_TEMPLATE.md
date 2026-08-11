## Objective

Describe the backup/retention/restore behavior this change adds or fixes.

## Evidence

- Exact source revision:
- Test output (`npm test`):
- Negative paths exercised (missing/invalid key, `/dashboard` reachability):
- Hosted CI run:

## Security and release impact

- [ ] No secrets (`ECHO_API_KEY`) are included.
- [ ] The `X-Echo-API-Key` / `checkAuth` authentication boundary is unchanged, or the change is
      called out explicitly.
- [ ] `/dashboard` stays reachable and `/` stays the plain-JSON public contract, or the change to
      that routing is called out explicitly.
- [ ] Retention/deletion logic changes are called out explicitly (this service deletes real R2
      objects and D1 rows).
