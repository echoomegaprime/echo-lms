r"""Critical journey for the ECHO Certification Forge.

The Forge runs this argv (declared as a top-level `journey` field in the
POST /v1/certifications request body -- NOT read from .echo/certification.json;
see [[reference-certification-forge-submit-recipe-20260810]] gotcha #8) inside
its isolated `python:3.12-alpine` sandbox, against the exact acquired commit,
with no network and no Node -- so the Worker itself cannot actually run, and
there is no `git` binary either (gotcha #9 of the same recipe). The full
behavioural suite (`npm test` -- typecheck plus the real auth test suite, run
against the actual `src/index.ts` via Node's native TypeScript support) runs
in CI on this same commit; this journey proves the artifact the Forge
actually acquired is the intact, complete Worker source -- not that it
currently boots.

This repository is TypeScript-only (a single Cloudflare Worker, Hono + D1 +
KV, no other framework); this journey therefore checks structural and
textual invariants rather than parsing Python.

Checks:
  1. The critical surfaces exist -- the Worker entrypoint, its test file, and
     the pinned Node dependency manifest.
  2. `src/index.ts` has not been truncated -- a cheap, tokenizer-free line
     and byte-size floor.
  3. No install-lifecycle scripts have crept into `package.json`.
  4. No hardcoded secret-shaped literals in the acquired source.
  5. The API key check still calls the constant-time `timingSafeEqual`
     rather than a raw `!==` -- functional tests can't distinguish a
     timing-safe comparison from a raw one (both return the same true/false),
     so this text-pattern check is the ONLY regression guard for that fix.
  6. The auth middleware's public-path exemption is still exactly the
     narrowed list from this consolidation pass -- not the original blanket
     `c.req.method === 'GET'` bypass that exempted every GET request,
     including management reads exposing student PII and revenue analytics.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
from typing import NoReturn

CRITICAL_SURFACES = (
    "src/index.ts",
    "tests/auth.test.mjs",
    "package.json",
    "tsconfig.json",
)

INSTALL_LIFECYCLE_HOOKS = ("preinstall", "install", "postinstall", "prepare")

SECRET_LITERAL_PATTERN = re.compile(
    r'(?:api_key|secret|password|token)\s*=\s*["\'][a-zA-Z0-9_\-]{16,}["\']',
    re.IGNORECASE,
)

MIN_INDEX_TS_LINES = 900
MIN_INDEX_TS_BYTES = 25_000

REQUIRED_PUBLIC_PATH_FRAGMENTS = (
    "path === '/'",
    "path === '/health'",
    "path === '/status'",
    "path.startsWith('/public/')",
    "path === '/webhooks/stripe'",
    "path.startsWith('/certificates/verify/')",
)


def _fail(message: str) -> NoReturn:
    print(f"ECHO_LMS_CRITICAL_JOURNEY_FAILED: {message}", file=sys.stderr)
    raise SystemExit(1)


def check_critical_surfaces() -> None:
    for surface in CRITICAL_SURFACES:
        if not pathlib.Path(surface).exists():
            _fail(f"missing critical surface: {surface}")


def _source_text() -> str:
    return pathlib.Path("src/index.ts").read_text(encoding="utf-8")


def check_index_ts_not_truncated() -> None:
    text = _source_text()
    line_count = text.count("\n") + 1
    byte_size = len(text.encode("utf-8"))
    if line_count < MIN_INDEX_TS_LINES:
        _fail(f"src/index.ts has only {line_count} lines (expected >= {MIN_INDEX_TS_LINES}) -- possible truncation")
    if byte_size < MIN_INDEX_TS_BYTES:
        _fail(f"src/index.ts is only {byte_size} bytes (expected >= {MIN_INDEX_TS_BYTES}) -- possible truncation")
    if "export default" not in text:
        _fail("src/index.ts is missing its 'export default' Worker entrypoint")


def check_no_install_hooks() -> None:
    manifest = pathlib.Path("package.json")
    try:
        scripts = json.loads(manifest.read_text(encoding="utf-8")).get("scripts", {})
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        _fail(f"package.json is not valid JSON: {exc}")
    present = sorted(hook for hook in INSTALL_LIFECYCLE_HOOKS if hook in scripts)
    if present:
        _fail(f"package.json reintroduced install-lifecycle script(s): {', '.join(present)}")


def check_no_hardcoded_secrets() -> None:
    match = SECRET_LITERAL_PATTERN.search(_source_text())
    if match:
        _fail(f"src/index.ts contains a hardcoded secret-shaped literal: {match.group(0)[:40]}...")


def check_constant_time_auth() -> None:
    text = _source_text()
    if "timingSafeEqual(key, c.env.ECHO_API_KEY)" not in text:
        _fail("the auth middleware no longer calls timingSafeEqual on the API key comparison")
    if re.search(r"key\s*!==\s*c\.env\.ECHO_API_KEY", text):
        _fail("the auth middleware regressed to a raw !== comparison")


def check_public_path_exemption_intact() -> None:
    text = _source_text()
    for fragment in REQUIRED_PUBLIC_PATH_FRAGMENTS:
        if fragment not in text:
            _fail(f"the auth middleware's public-path exemption is missing: {fragment!r}")
    # The specific line that gates entry into the auth check must not have
    # grown a blanket method exemption re-appended to it -- this is exactly
    # how the original defect (every GET bypassed auth) looked in source.
    gate_match = re.search(r"if \(isPublicPath \|\| c\.req\.method === 'OPTIONS'([^)]*)\) return next\(\);", text)
    if not gate_match:
        _fail("could not find the isPublicPath gate line in its expected exact form")
    if gate_match.group(1).strip():
        _fail(
            f"the isPublicPath gate has extra conditions appended: {gate_match.group(1)!r} -- "
            f"this is exactly the shape of the original 'every GET bypasses auth' defect"
        )


def main() -> None:
    check_critical_surfaces()
    check_index_ts_not_truncated()
    check_no_install_hooks()
    check_no_hardcoded_secrets()
    check_constant_time_auth()
    check_public_path_exemption_intact()
    print(
        "ECHO_LMS_CRITICAL_JOURNEY_OK "
        "critical_surfaces=4 install_hooks=0 hardcoded_secrets=0 "
        "constant_time_auth=1 public_path_exemption_intact=1"
    )


if __name__ == "__main__":
    main()
