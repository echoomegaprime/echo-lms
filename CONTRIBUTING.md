# Contributing

Thank you for improving Echo LMS. This is a public, proprietary infrastructure project:
contributions are welcome for review, but repository visibility does not grant a general use
or redistribution license.

## Development path

1. Open an issue describing the behavior being changed.
2. Create a focused branch from current `main`.
3. Add a failing test before changing the auth middleware's `isPublicPath` list or
   `timingSafeEqual` -- see SECURITY.md for exactly which routes are public and why.
4. Validate before opening a pull request:

   ```powershell
   npm install
   npm test
   ```

5. Open a pull request using the repository template and include exact test output.

## Pull-request requirements

- No secrets (`ECHO_API_KEY`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `LMS_HMAC_KEY`)
  are included.
- No stubs, placeholders, or self-asserted readiness -- this service holds student PII and
  processes real Stripe payments.
- **Any change that adds a path to the auth middleware's public exemption list must be called
  out explicitly in the pull request description**, with the reason the new route is safe to
  leave unauthenticated -- this is exactly the class of change that introduced the bug fixed
  in this consolidation pass.
