# WebHawk Webhook Security Proxy

**"Assume every incoming request is forged until proven otherwise."**
— OWASP Webhook Security Guidelines

WebHawk is an enterprise-grade proxy and auditor deployed on Cloudflare Workers that verifies webhook authenticity in real time before forwarding events to internal services. It implements industry-standard security protocols for webhooks, validated against specifications from Stripe, Wompi, GitHub, and OWASP.

---

## Architecture

```
[Webhook Provider] → [WebHawk Proxy (Cloudflare Edge)]
                               ↓
          [1. IP Whitelisting (CIDR validation)]
                               ↓
          [2. Rate Limiting (DoS protection)]
                               ↓
          [3. HMAC-SHA256 Verification (constant-time)]
                               ↓ (fail → 401, log, stop)
          [4. Timestamp Validation (±5min window)]
                               ↓ (fail → 401, log, stop)
          [5. Event Deduplication (KV TTL 24h)]
                               ↓ (dup → 200 silent, stop)
          [6. Audit Log (No secrets, no PII)]
                               ↓
          [7. Forwarding (SSRF-protected)]
```

The pipeline execution order is non-negotiable. Timestamp validation runs after HMAC verification to prevent unsigned requests from generating unnecessary log volume. Deduplication returns HTTP 200 rather than 4xx/5xx to prevent provider retry loops.

---

## Security Specifications

| Specification | Status | Implementation |
|---|---|---|
| HMAC-SHA256 over raw bytes (never re-parsed JSON) | Implemented | `crypto.utils.ts:hmacSha256()` |
| Constant-time comparison (`crypto.subtle.timingSafeEqual`) | Implemented | `crypto.utils.ts:timingSafeCompare()` |
| Timestamp validation (±5min + 30s clock skew buffer) | Implemented | `timestamp.middleware.ts` |
| Event deduplication by event ID with KV TTL | Implemented | `dedup.middleware.ts` |
| Secret rotation with overlap window | Implemented | All verifiers (e.g. `STRIPE_WEBHOOK_SECRET_PREV`) |
| Rate limiting and payload size constraint (1MB limit) | Implemented | `rate-limit.middleware.ts` |
| SSRF protection on forwarding | Implemented | `ssrf.guard.ts` |
| Egress request signing | Implemented | `forwarder.ts` |
| CIDR IP whitelisting | Implemented | `ip-whitelist.middleware.ts` |

---

## Supported Providers

| Provider | Signature Scheme | Header |
|---|---|---|
| Wompi | SHA-256 field checksum | `X-Event-Checksum` |
| Wompi | HMAC-SHA256 over raw body | `wompi_hash` |
| Stripe | HMAC-SHA256 over `t.rawBody` | `Stripe-Signature` |
| GitHub | HMAC-SHA256 over raw body | `X-Hub-Signature-256` |

Extending support to a new provider requires implementing `WebhookVerifier<Env>` and registering it in `src/index.ts`. No pipeline modifications are necessary, adhering to the Open/Closed Principle.

---

## Endpoints

```http
GET  /health                  → Service status and registered providers
POST /webhook/:provider       → Webhook proxy entry point
  Example: POST /webhook/stripe
```

---

## Development and Deployment

### Setup Instructions

```bash
# Install dependencies
npm install

# Execute comprehensive test suite (including attack simulations)
npm test

# Initialize local development server
npm run dev

# Execute static type analysis
npm run typecheck
```

### Environment Configuration

Configure the following variables in `wrangler.toml` or the Cloudflare Workers dashboard:

```toml
ENVIRONMENT = "production"

# Wompi Configuration
WOMPI_SECRET = "primary_secret"
WOMPI_SECRET_PREV = "previous_secret"

# Stripe Configuration
STRIPE_WEBHOOK_SECRET = "primary_secret"
STRIPE_WEBHOOK_SECRET_PREV = "previous_secret"

# GitHub Configuration
GITHUB_WEBHOOK_SECRET = "primary_secret"
GITHUB_WEBHOOK_SECRET_PREV = "previous_secret"

# Egress Signing Configuration
EGRESS_SIGNING_SECRET = "internal_secret"
EGRESS_SIGNING_SECRET_PREV = "previous_internal_secret"
```

---

## Test Suite and Attack Simulations

The WebHawk testing methodology prioritizes adversarial scenarios over standard functional coverage. The suite simulates the following attack vectors:

| Module | Simulated Vector |
|---|---|
| `invalid-signature.spec.ts` | Forged HMAC, invalid secrets, tampered payloads |
| `expired-timestamp.spec.ts` | Replay attacks utilizing historical or future timestamps |
| `replay-event.spec.ts` | Duplicate event submission and event ID stability |
| `timing-attack.spec.ts` | Timing side-channel attacks on signature comparison |
| `ssrf.spec.ts` | Server-Side Request Forgery via private IPs, non-HTTP schemes, and restricted ports |
| `secret-rotation.spec.ts` | Secret rotation overlap windows and expired secrets |

---

## Threat Model

The core principle of WebHawk is zero-trust validation.

| Threat Vector | Mitigation Strategy |
|---|---|
| Forged webhook (invalid cryptographic signature) | HMAC verification rejects request with HTTP 401 |
| Timing side-channel attack | `crypto.subtle.timingSafeEqual` ensures constant-time comparison |
| Replay attack (valid historical event) | Enforced timestamp window (± 5 minutes) |
| Replay within valid temporal window | Cloudflare KV deduplication keyed by event ID |
| Provider retry loop exhaustion | Duplicate events return HTTP 200 silently |
| Denial of Service (DoS) via request saturation | IP and provider-level rate limiting |
| Volumetric payload attacks | Strict 1MB body size limit enforcement |
| Server-Side Request Forgery (SSRF) | Network guard blocks private and reserved IP spaces |
| Secret exposure in telemetry | AuditLogger redacts all secrets and payload content |
| Downtime during credential rotation | Supported overlap window utilizing `*_PREV` environment variables |

---

## Technology Stack

- **Runtime**: Cloudflare Workers (Edge execution, sub-millisecond cold start)
- **Framework**: Hono (Web Standards compliant)
- **Cryptography**: `crypto.subtle` (Native Web Crypto API)
- **State Management**: Cloudflare KV (Rate limiting, deduplication, audit persistence)
- **Testing**: Vitest with `@cloudflare/vitest-pool-workers`

---

## License

MIT © WebHawk Contributors
