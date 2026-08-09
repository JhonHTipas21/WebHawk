# WebHawk — Real-Time Webhook Security Auditor

> **"Assume every incoming request is forged until proven otherwise."**
> — OWASP Webhook Security Guidelines 2026

WebHawk is a proxy/auditor deployed on **Cloudflare Workers** that verifies webhook authenticity in real time before forwarding events to your services. It implements the industry-standard 2026 security checklist for webhooks, validated against documentation from Stripe, Wompi, GitHub, and OWASP.

---

## Architecture

```
[Webhook Provider] → [WebHawk Proxy (Cloudflare Edge)]
                              ↓
          [1. Rate Limiting (DoS protection)]
                              ↓
          [2. Raw Body Capture (BEFORE any parsing)]
                              ↓
          [3. HMAC-SHA256 Verification (constant-time)]
                              ↓ (fail → 401, log, stop)
          [4. Timestamp Validation (±5min window)]
                              ↓ (fail → 401, log, stop)
          [5. Event Deduplication (KV TTL 24h)]
                              ↓ (dup → 200 silent, stop)
          [6. Audit Log (no secrets, no PII)]
                              ↓
          [7. Forward to real service (SSRF-protected)]
```

**The order is non-negotiable.** Timestamp validation runs after HMAC verification to prevent unsigned requests from causing unnecessary log noise. Deduplication returns 2xx (not 4xx) to prevent provider retry loops.

---

## Security Checklist (2026 Standard)

| # | Check | Status | Implementation |
|---|---|---|---|
| 1 | HMAC-SHA256 over **raw bytes** (never re-parsed JSON) | ✅ | `crypto.utils.ts:hmacSha256()` |
| 2 | **Constant-time comparison** (`crypto.subtle.timingSafeEqual`) | ✅ | `crypto.utils.ts:timingSafeCompare()` |
| 3 | Timestamp validation (±5min + 30s clock skew buffer) | ✅ | `timestamp.middleware.ts` |
| 4 | Event deduplication by event ID with KV TTL | ✅ | `dedup.middleware.ts` |
| 5 | Secret rotation with overlap window | ✅ | All verifiers: `WOMPI_SECRET_PREV` etc. |
| 6 | Rate limiting + body size limit (1MB) | ✅ | `rate-limit.middleware.ts` |
| 7 | SSRF protection on forwarding | ✅ | `ssrf.guard.ts` |
| 8 | No logging of secrets or full payload | ✅ | `audit.logger.ts` |

---

## Supported Providers

| Provider | Signature Scheme | Header |
|---|---|---|
| **Wompi** | SHA-256 field checksum | `X-Event-Checksum` |
| **Wompi** | HMAC-SHA256 over raw body | `wompi_hash` |
| **Stripe** | HMAC-SHA256 over `t.rawBody` | `Stripe-Signature` |
| **GitHub** | HMAC-SHA256 over raw body | `X-Hub-Signature-256` |

Adding a new provider: implement `WebhookVerifier<Env>` and register it in `src/index.ts` — no pipeline changes needed (Open/Closed Principle).

---

## Endpoints

```
GET  /health                  → Service status + registered providers
POST /webhook/:provider       → Webhook proxy entry point
  e.g. POST /webhook/wompi
       POST /webhook/stripe
       POST /webhook/github
```

---

## Development

```bash
# Install dependencies
npm install

# Run tests (including attack simulations)
npm test

# Run in local dev mode
npm run dev

# TypeScript type check
npm run typecheck
```

### Environment Variables

```toml
# wrangler.toml / Cloudflare Workers dashboard
WOMPI_SECRET = "your_wompi_integration_secret"
WOMPI_SECRET_PREV = ""          # Previous secret during rotation

STRIPE_WEBHOOK_SECRET = "whsec_..."
STRIPE_WEBHOOK_SECRET_PREV = "" # Previous secret during rotation

GITHUB_WEBHOOK_SECRET = "your_github_webhook_secret"
GITHUB_WEBHOOK_SECRET_PREV = "" # Previous secret during rotation

ENVIRONMENT = "production"
```

---

## Test Suite — Attack Simulations

WebHawk's tests prioritize **attack scenarios** over happy-path coverage:

| Test File | Attack Simulated |
|---|---|
| `invalid-signature.spec.ts` | Forged HMAC, wrong secret, tampered body |
| `expired-timestamp.spec.ts` | Replay with old timestamp, future timestamp |
| `replay-event.spec.ts` | Duplicate event (retry), event ID stability |
| `timing-attack.spec.ts` | Timing side-channel on comparison |
| `ssrf.spec.ts` | SSRF via private IPs, HTTP, internal ports |
| `secret-rotation.spec.ts` | Overlap window, expired secrets |

```bash
npm test
# Runs all 6 attack simulation test suites + unit tests
```

---

## Threat Model

**Principle**: Every incoming request is treated as forged until proven otherwise.

| Threat | Mitigation |
|---|---|
| Forged webhook (no valid key) | HMAC verification rejects with 401 |
| Timing side-channel attack | `crypto.subtle.timingSafeEqual` constant-time compare |
| Replay attack (old valid event) | Timestamp window ± 5 min |
| Replay within valid window | KV deduplication by event ID |
| Provider retry loops | Duplicates return 2xx silently |
| DoS via webhook spam | Rate limiting (60 req/min/IP) |
| Oversized body attacks | 1MB body size limit |
| SSRF via forwarding URL | SSRF guard blocks private IPs |
| Secret exposure in logs | AuditLogger never logs secrets/payload |
| Secret rotation breakage | Overlap window with `*_PREV` secrets |

---

## Tech Stack

- **Runtime**: Cloudflare Workers (edge, <1ms cold start)
- **Framework**: Hono v4 (Web Standards-native)
- **Crypto**: `crypto.subtle` (Web Crypto API, no Node.js compat needed)
- **Deduplication**: Cloudflare KV (24h TTL per event)
- **Testing**: Vitest with `@cloudflare/vitest-pool-workers`
- **CI/CD**: GitHub Actions → Cloudflare Workers deploy

---

## License

MIT © 2026 WebHawk Contributors
