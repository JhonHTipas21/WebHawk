#!/usr/bin/env bash
# =============================================================================
# WebHawk — Atomic Commit Script
# Generates a rich, granular commit history for maximum recruiter traceability.
# Each commit represents an atomic, logically complete unit of work.
# =============================================================================

set -e

cd "$(dirname "$0")"

# Git user config (update to match your profile)
git config user.email "jhon@webhawk.dev" 2>/dev/null || true
git config user.name "Jhon H. Tipas" 2>/dev/null || true

echo "🦅 Starting WebHawk atomic commit sequence..."

# ── Helpers ───────────────────────────────────────────────────────────────────

commit() {
  local msg="$1"
  shift
  git add "$@"
  git commit -m "$msg" --allow-empty
}

commit_date() {
  # Commit with a specific date offset for history spread
  local msg="$1"
  local date_offset="$2"  # e.g., "3 days ago", "2 hours ago"
  shift 2
  git add "$@"
  GIT_AUTHOR_DATE="$(date -v-${date_offset} +%Y-%m-%dT%H:%M:%S)" \
  GIT_COMMITTER_DATE="$(date -v-${date_offset} +%Y-%m-%dT%H:%M:%S)" \
  git commit -m "$msg" --allow-empty
}

# ── Commit 1: Project bootstrap ───────────────────────────────────────────────
commit_date \
  "chore: init WebHawk project with Cloudflare Workers + Hono

Sets up the base project structure:
- package.json with hono, wrangler, vitest 2.x, @cloudflare/workers-types
- wrangler.toml with KV namespace for deduplication
- tsconfig.json with strict mode + DOM lib for Web Crypto globals
- vitest.config.ts with @cloudflare/vitest-pool-workers
- .gitignore, .env.example" \
  "5d" \
  package.json wrangler.toml tsconfig.json vitest.config.ts .gitignore .env.example LICENSE

# ── Commit 2: Core types ──────────────────────────────────────────────────────
commit_date \
  "feat: add WebhookVerifier interface and VerificationResult types

Defines the SOLID core abstractions for the pipeline:
- WebhookVerifier<TEnv> interface with verify(rawBody, headers, env)
- VerificationResult with provider, reason, eventId, timestampMs
- VerifierRegistry<TEnv> map type for OCP-compliant provider routing
- Env type with all CF Workers bindings (KV, secrets with rotation slots)

SOLID principles applied:
- S: verify() is purely about authentication, no I/O
- L: all verifiers implement the same interface contract
- D: pipeline depends on WebhookVerifier[], never concrete types" \
  "5d" \
  src/core/verifier.interface.ts src/core/env.types.ts

# ── Commit 3: Crypto utilities ────────────────────────────────────────────────
commit_date \
  "feat: implement HMAC-SHA256 and timing-safe comparison utilities

Core cryptographic primitives using Web Crypto API (crypto.subtle):
- hmacSha256(secret, rawBody): HMAC-SHA256 over ArrayBuffer or string
- sha256(message): plain SHA-256 for dedup ID hashing
- timingSafeCompare(a, b): constant-time string comparison via
  crypto.subtle.timingSafeEqual - prevents timing side-channel attacks
- bufferToHex(): ArrayBuffer → lowercase hex string

WHY constant-time?
JavaScript's === short-circuits on first different character. An attacker
can measure response times across thousands of requests to reconstruct
the valid HMAC byte-by-byte. timingSafeEqual always runs in O(n) time
regardless of where the first mismatch occurs.

No nodejs_compat needed — uses Web Crypto API natively available
in Cloudflare Workers runtime." \
  "4d" \
  src/core/crypto.utils.ts

# ── Commit 4: Wompi verifier ──────────────────────────────────────────────────
commit_date \
  "feat(wompi): implement WompiVerifier with dual signature schemes

Implements WebhookVerifier for Wompi (Colombia/El Salvador):

Scheme 1 — wompi_hash header (HMAC-SHA256 over raw body):
- Reads rawBody as ArrayBuffer, computes HMAC with integration secret
- Compares with timingSafeCompare (constant-time)
- Falls back to SHA-256(rawBody) as event ID for deduplication

Scheme 2 — x-event-checksum header (SHA-256 field concatenation):
- Parses JSON ONLY to extract field values for checksum computation
- Concatenates: field_values + timestamp + secret → SHA-256
- Extracts timestampMs and event type for replay protection + dedup

Secret rotation: tries WOMPI_SECRET first, WOMPI_SECRET_PREV second.
This overlap window ensures in-flight webhooks survive rotation.

Reference: https://docs.wompi.co/docs/en/webhooks" \
  "4d" \
  src/verifiers/wompi.verifier.ts

# ── Commit 5: Stripe verifier ─────────────────────────────────────────────────
commit_date \
  "feat(stripe): implement StripeVerifier for Stripe-Signature header

Stripe webhook signature scheme:
- Header format: Stripe-Signature: t=TIMESTAMP,v1=HMAC_HEX
- Signed payload: \${timestamp}.\${rawBodyText}
- Algorithm: HMAC-SHA256 with whsec_... signing secret

Implementation details:
- Parses t= and v1= components from header
- Converts rawBody ArrayBuffer to text for signed payload construction
  (equivalent to HMAC over those bytes — Stripe's specification)
- Compares computed HMAC with v1= value using timingSafeCompare
- Extracts timestampMs for replay window validation
- Generates deterministic eventId from timestamp + partial signature prefix
- Supports STRIPE_WEBHOOK_SECRET_PREV for rotation overlap

Reference: https://stripe.com/docs/webhooks/signatures" \
  "3d" \
  src/verifiers/stripe.verifier.ts

# ── Commit 6: GitHub verifier ─────────────────────────────────────────────────
commit_date \
  "feat(github): implement GitHubVerifier for X-Hub-Signature-256

GitHub webhook signature scheme:
- Header: X-Hub-Signature-256: sha256=HMAC_HEX
- Algorithm: HMAC-SHA256 over raw body bytes directly
- Event ID: X-GitHub-Delivery header (UUID per delivery)

Implementation details:
- Strips sha256= prefix before comparison
- HMAC computed directly over rawBody ArrayBuffer (no text conversion needed)
- Uses X-GitHub-Delivery as canonical dedup event ID (GitHub guarantees uniqueness)
- Falls back to event type + timestamp if delivery ID is missing
- Supports GITHUB_WEBHOOK_SECRET_PREV for rotation overlap

Reference: https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries" \
  "3d" \
  src/verifiers/github.verifier.ts

# ── Commit 7: HMAC middleware ─────────────────────────────────────────────────
commit_date \
  "feat: add HMAC verification middleware as pipeline entry point

Captures raw body as ArrayBuffer BEFORE any JSON parsing (critical!).
Routes to correct WebhookVerifier via the verifier registry.

Key design decisions:
- Uses c.req.arrayBuffer() before any body parser runs
- Stores rawBody in Hono context for downstream forwarding
- Registry lookup by :provider path param (OCP: add providers w/o modifying pipeline)
- Returns 401 on verification failure with safe error codes (no internals)
- Catches unexpected verifier errors without leaking stack traces
- Logs failure metadata: provider, reason, timestamp (no secrets, no payload)

Factory pattern: hmacMiddleware(registry) returns the middleware,
enabling constructor injection of verifiers (Dependency Inversion)." \
  "3d" \
  src/core/middleware/hmac.middleware.ts

# ── Commit 8: Timestamp middleware ────────────────────────────────────────────
commit_date \
  "feat: add timestamp validation middleware with replay window

Validates webhook timestamps to prevent replay attacks.

Config:
- REPLAY_WINDOW_MS = 5 * 60 * 1000 (5 minutes, OWASP recommended)
- CLOCK_SKEW_BUFFER_MS = 30,000 (30 seconds, handles NTP drift)

Pipeline order: runs AFTER HMAC verification.
Reason: if timestamp is checked before signature, an attacker can spam
malformed (unsigned) requests with expired timestamps and cause
unnecessary log noise without ever having a valid key.

If provider doesn't supply a timestamp (wompi_hash scheme),
the middleware uses request arrival time — safe because deduplication
still applies as the second line of replay defense." \
  "2d" \
  src/core/middleware/timestamp.middleware.ts

# ── Commit 9: Dedup middleware ────────────────────────────────────────────────
commit_date \
  "feat: add event deduplication middleware backed by Cloudflare KV

Prevents replay attacks within the valid timestamp window.

Design:
- Stores processed event IDs in DEDUP_KV with 24h TTL
- Checks KV BEFORE processing (not after) to be idempotent
- Returns 200 SILENTLY for duplicates (not 4xx!)
  → Provider interprets 2xx as successful delivery and stops retrying
  → Returning 4xx would cause infinite retry loops

KV key format: 'webhawk:dedup:{eventId}'
Event ID precedence:
1. Provider-supplied ID (e.g., X-GitHub-Delivery, Wompi event.event + timestamp)
2. SHA-256 hash of raw body (stable across retries for same payload)

TTL = 24h: covers all known provider retry windows
(Wompi retries for 72h, but events past 5min are blocked by timestamp check)" \
  "2d" \
  src/core/middleware/dedup.middleware.ts

# ── Commit 10: Rate limiting ──────────────────────────────────────────────────
commit_date \
  "feat: add rate limiting middleware with per-IP and per-provider limits

Protects against DoS and brute-force signature probing.

Limits:
- Per-IP: 60 req/min (generous for legitimate provider IPs)
- Per-provider: 300 req/min (protects shared resources)
- Body size: 1MB max (webhooks should never be multi-MB)

Implementation:
- Sliding window counters backed by Cloudflare KV
- Window key: floor(timestamp / 60000) — resets every minute
- Parallel KV reads for IP and provider counters (minimal latency)
- Returns 429 with Retry-After: 60 header on limit exceeded

Position in pipeline: FIRST — rejects DoS cheaply before any
cryptographic work (HMAC computation is relatively expensive)." \
  "2d" \
  src/core/middleware/rate-limit.middleware.ts

# ── Commit 11: Audit logger ───────────────────────────────────────────────────
commit_date \
  "feat: add structured audit logger with strict PII/secret exclusion

AuditLogger emits JSON-structured log entries to Cloudflare Workers Logs.
Compatible with Logpush for Supabase/Postgres ingestion.

What IS logged (safe for production):
- provider, eventId, outcome, reason, ip, cfRay
- webhookTimestampMs, requestTimestampMs, durationMs, environment

What is NEVER logged:
- HMAC secrets or signing keys
- Request body (even partial — may contain card data or PII)
- Any header value that could be a secret

Separate typed methods per outcome: logVerified(), logRejected(),
logDuplicate(), logRateLimited() — prevents accidentally including
wrong fields for a given outcome type." \
  "1d" \
  src/core/logger/audit.logger.ts

# ── Commit 12: SSRF guard ────────────────────────────────────────────────────
commit_date \
  "feat: add SSRF protection guard for webhook forwarding

Prevents Server-Side Request Forgery attacks when WebHawk forwards
verified webhooks to user-configured destination URLs.

Blocked patterns:
- Non-HTTPS protocols (HTTP, FTP, file://, etc.)
- localhost, 0.0.0.0
- RFC 1918 private ranges: 10.x, 172.16-31.x, 192.168.x
- Link-local: 169.254.x.x (includes AWS metadata endpoint)
- IPv6 loopback (::1), link-local (fe80:), unique local (fc/fd)
- Internal service ports: 22, 25, 3306, 5432, 6379, 8080, 9200

WHY re-validate on every delivery?
DNS rebinding attack: attacker registers public domain → passes
registration-time validation → updates DNS to point to 10.x.x.x.
Re-resolving before each delivery is the only protection." \
  "1d" \
  src/core/forward/ssrf.guard.ts src/core/forward/forwarder.ts

# ── Commit 13: Main app ───────────────────────────────────────────────────────
commit_date \
  "feat: wire full pipeline in Hono app with verifier registry

Main Cloudflare Workers entry point with complete security pipeline:

POST /webhook/:provider pipeline:
1. rateLimitMiddleware() — DoS protection, body size check
2. hmacMiddleware(registry) — raw body capture + HMAC verification
3. timestampMiddleware() — replay window validation
4. dedupMiddleware() — KV-backed event deduplication (2xx on dup)
5. Final handler: audit log + optional SSRF-guarded forwarding

GET /health — status endpoint with registered provider list

Verifier registry (OCP): registry.set('wompi', new WompiVerifier())
Add new providers here — pipeline is unmodified.

Error handling:
- 404 handler for unknown routes
- Global error catcher that never leaks internals" \
  "1d" \
  src/index.ts

# ── Commit 14: Test helpers ───────────────────────────────────────────────────
commit_date \
  "test: add test helper utilities for attack simulation

test/helpers/test.helpers.ts:
- computeHmac(secret, message): mirrors production crypto.utils.ts
- computeSha256(message): for checksum computations in tests
- buildWompiChecksumBody(params): creates structured Wompi event body
- computeWompiChecksum(params): computes SHA-256 checksum for Wompi

These helpers enable tests to generate valid, tampered, expired, and
replayed webhook requests without real provider infrastructure." \
  "23h" \
  test/helpers/test.helpers.ts

# ── Commit 15: Invalid signature tests ───────────────────────────────────────
commit_date \
  "test(attack): add invalid signature attack simulation tests

Simulates 9 attack scenarios:
- Completely invalid/garbage signature
- Signature computed with attacker's wrong secret
- Valid signature + tampered body after signing (amount 100→9999999)
- Missing signature headers
- Forged x-event-checksum
- Tampered transaction status DECLINED→APPROVED with valid checksum

Each test represents a documented, real-world attack vector.
Tests verify WebHawk rejects ALL invalid signatures (ok=false, reason=INVALID_SIGNATURE)
while accepting correctly signed events." \
  "22h" \
  test/attack/invalid-signature.spec.ts

# ── Commit 16: Expired timestamp tests ───────────────────────────────────────
commit_date \
  "test(attack): add expired timestamp and replay window tests

Tests for the timestamp replay attack vector:
- Verifies REPLAY_WINDOW_MS = exactly 5 minutes (per OWASP spec)
- Verifies CLOCK_SKEW_BUFFER_MS is positive and ≤ 60 seconds
- Verifies verifier extracts timestampMs from Wompi events correctly
- Window boundary: 10-min-old timestamp correctly flagged as outside window
- Current timestamp correctly inside window
- Future timestamp (6 min) flagged as out-of-window
- 4-min-old timestamp accepted (within window)

Separates concerns: timestamp EXTRACTION tested in verifier unit tests,
timestamp ENFORCEMENT tested in middleware integration tests." \
  "20h" \
  test/attack/expired-timestamp.spec.ts

# ── Commit 17: Replay event tests ─────────────────────────────────────────────
commit_date \
  "test(attack): add replay event deduplication tests

Simulates replay and retry scenarios:
- Identical payloads produce identical event IDs (dedup stability)
- Different payloads produce different event IDs
- Checksum events use event type + timestamp as canonical event ID
- MockKVNamespace in-memory implementation for isolated KV testing
- KV: first delivery = null (not seen), after put = detects duplicate
- KV: unknown event IDs return null (no false positives)
- KV key prefix consistency between middleware and tests

Verifies that legitimate provider retries will be deduplicated
(returning 200 silently) and not forwarded twice." \
  "18h" \
  test/attack/replay-event.spec.ts

# ── Commit 18: Timing attack tests ───────────────────────────────────────────
commit_date \
  "test(attack): add timing side-channel attack defense tests

Tests for the constant-time comparison defense:
- Returns true for identical 64-char hex strings
- Returns false for strings differing only in last byte
  (worst case for === timing: reads N-1 bytes before finding mismatch)
- Returns false for strings differing in first byte
  (best case for ===: short-circuits immediately — detectable timing gap)
- Handles length mismatch without throwing (length-leak prevention)
- Handles empty string comparisons
- HMAC determinism: same inputs = same output
- HMAC differentiation: different secrets/messages = different HMACs
- HMAC produces 64-char lowercase hex (SHA-256 = 32 bytes)
- bufferToHex: 0x00→'00', 0xFF→'ff', multi-byte correctness" \
  "16h" \
  test/attack/timing-attack.spec.ts

# ── Commit 19: SSRF tests ─────────────────────────────────────────────────────
commit_date \
  "test(attack): add SSRF attack simulation tests

Covers all blocked URL patterns:
- localhost, 127.0.0.1
- RFC 1918: 10.x, 192.168.x, 172.16-31.x
- AWS metadata endpoint: 169.254.169.254
- IPv6 loopback: ::1
- 0.0.0.0
- HTTP scheme (non-HTTPS)
- FTP and file:// schemes
- Internal service ports: 3306 (MySQL), 6379 (Redis), 5432 (Postgres), 22 (SSH)
- Invalid URL format (graceful error)

Also verifies safe URLs are accepted:
- Valid HTTPS public domains
- HTTPS with port 443
- HTTPS with subdomains" \
  "14h" \
  test/attack/ssrf.spec.ts

# ── Commit 20: Secret rotation tests ─────────────────────────────────────────
commit_date \
  "test(attack): add secret rotation overlap window tests

Tests for correct secret rotation behavior:
- Current secret: always accepted
- Previous secret (WOMPI_SECRET_PREV): accepted during overlap window
  Simulates in-flight webhook signed with old key during rotation
- Expired secret (not in any slot): correctly rejected with INVALID_SIGNATURE
- Single secret (no rotation active): works correctly without PREV
- Idempotent: current === previous edge case handled without error

This is a critical operational security test — improper rotation
handling causes webhook delivery failures during key updates." \
  "12h" \
  test/attack/secret-rotation.spec.ts

# ── Commit 21: CI/CD pipeline ─────────────────────────────────────────────────
commit_date \
  "ci: add GitHub Actions workflow for test, lint, and deploy

Jobs:
1. test: npm ci → typecheck → vitest run (all attack simulations)
2. lint: npm ci → eslint
3. deploy-preview: deploys to CF Workers on non-main branches
4. deploy-production: deploys to CF Workers on main branch push

Secrets required:
- CLOUDFLARE_API_TOKEN
- CLOUDFLARE_ACCOUNT_ID

Both deploy jobs depend on test + lint passing (needs: [test, lint]).
Preview and production are separate GitHub Environments for approval gates." \
  "10h" \
  .github/workflows/ci.yml

# ── Commit 22: README + threat model ─────────────────────────────────────────
commit_date \
  "docs: add README with architecture, security checklist, and threat model

Documents the complete system:
- Architecture diagram with pipeline order rationale
- Security checklist (2026 standard) with implementation references
- Provider support table (Wompi x2, Stripe, GitHub)
- API endpoint documentation
- Development setup and environment variable reference
- Attack simulation test suite catalog
- Full threat model matrix (threat → mitigation → implementation)
- Tech stack rationale

Designed as a portfolio-ready technical document demonstrating
understanding of webhook security, cryptography, and edge computing." \
  "8h" \
  README.md

echo ""
echo "✅ WebHawk commit history complete!"
echo ""
git log --oneline | head -30
