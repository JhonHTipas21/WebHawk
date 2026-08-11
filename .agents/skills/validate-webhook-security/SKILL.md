---
name: validate-webhook-security
description: Guidelines and best practices for validating webhook signature, timestamp, deduplication, and preventing timing side-channel attacks.
---

# Webhook Security Validation Guide

This skill details the architectural rules and implementation patterns for verifying incoming webhooks securely at the edge.

## Verification Pipeline Order

To prevent resource exhaustion, denial of service (DoS), and log spamming, the verification pipeline must execute in the following strict order:

1.  **IP Whitelisting & CIDR Validation:** Filter incoming requests early based on provider IP ranges before parsing payloads.
2.  **Rate Limiting:** Protect edge resources by applying rate limits (per IP and per provider) before executing costly crypto checks.
3.  **HMAC Signature Verification:** Validate cryptographic authenticity.
4.  **Timestamp Validation:** Reject requests outside the tolerance window (typically ±5 minutes) to mitigate replay attacks.
5.  **Event Deduplication:** Check a persistent or KV store for duplicate event IDs to prevent duplicate processing.
6.  **Audit Logging:** Write telemetry data, ensuring no secrets or PII are logged.
7.  **Webhook Forwarding:** Forward validated requests to internal services securely.

## Cryptographic Best Practices

### HMAC-SHA256 Over Raw Bytes
Always verify the signature against the raw body buffer (`ArrayBuffer` or `Uint8Array`) received from the client. Never re-serialize or parse JSON before verification, as differences in formatting or property ordering will invalidate the signature.

```typescript
// Correct pattern:
const rawBody = await request.arrayBuffer();
const signature = await computeHmac(secret, rawBody);
```

### Constant-Time Signature Comparison
To prevent timing side-channel attacks, always compare signature strings using a constant-time comparison helper. Never use standard `===` or `!==` operators.

```typescript
// Correct pattern using Web Crypto API:
export function timingSafeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  const encoder = new TextEncoder();
  const aBuf = encoder.encode(a);
  const bBuf = encoder.encode(b);
  return crypto.subtle.timingSafeEqual(aBuf, bBuf);
}
```

## Replay Prevention

### Timestamp Window Validation
Reject requests whose embedded timestamp deviates by more than 5 minutes (plus a small clock skew buffer, e.g., 30 seconds) from the current edge server time.
Always execute timestamp check *after* signature verification to avoid processing arbitrary, spoofed timestamps.

### KV-Backed Deduplication
Use a distributed key-value store (e.g., Cloudflare KV) to register seen event IDs:
-   **TTL:** Keep event IDs in the store for 24 hours.
-   **Response:** If a duplicate event ID is detected, return an HTTP 200 silently with a header indicating it was deduplicated (e.g., `X-Webhawk-Dedup: true`). Do not return a 4xx/5xx code, as this would trigger webhook provider retry loops.
