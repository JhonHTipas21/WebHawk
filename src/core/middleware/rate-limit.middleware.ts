/**
 * @file rate-limit.middleware.ts
 * @description Rate limiting middleware for WebHawk webhook endpoints.
 *
 * THREAT: Denial of Service + Brute-Force Signature Guessing.
 * An attacker can spam thousands of requests/second to:
 * a) Overwhelm the worker CPU budget.
 * b) Probe signature values (even with timing-safe compare, volume limits reduce risk).
 *
 * IMPLEMENTATION:
 * Uses a sliding window counter backed by Cloudflare KV for compatibility
 * across all environments. In production, Cloudflare's native Rate Limiting
 * Rules (Ruleset Engine) should also be configured for network-layer protection.
 *
 * Limits:
 * - Per-IP: 60 requests / minute (generous for legitimate providers)
 * - Per-provider: 300 requests / minute (protects shared resources)
 *
 * Body size: Cloudflare Workers default max is 100MB. We enforce a tighter
 * limit of 1MB for webhook endpoints (webhooks should never be multi-MB).
 */

import type { Context, Next } from 'hono';
import type { Env, Variables } from '../env.types.js';

const RATE_WINDOW_MS = 60_000; // 1 minute sliding window
const MAX_REQUESTS_PER_IP = 60;
const MAX_REQUESTS_PER_PROVIDER = 300;
const MAX_BODY_BYTES = 1 * 1024 * 1024; // 1MB

const KV_RATE_PREFIX = 'webhawk:rate:';

export function rateLimitMiddleware() {
  return async (c: Context<{ Bindings: Env; Variables: Variables }>, next: Next): Promise<Response | void> => {
    // ── Body size check (fast, no I/O) ────────────────────────────────────────
    const contentLength = c.req.header('content-length');
    if (contentLength && parseInt(contentLength, 10) > MAX_BODY_BYTES) {
      return c.json(
        { error: 'Request body too large', code: 'BODY_TOO_LARGE' },
        413,
      );
    }

    // ── Extract rate limit keys ───────────────────────────────────────────────
    const ip = c.req.header('cf-connecting-ip') ?? 'unknown';
    const provider = c.req.param('provider') ?? 'unknown';
    const windowKey = Math.floor(Date.now() / RATE_WINDOW_MS);

    const ipKey = `${KV_RATE_PREFIX}ip:${ip}:${windowKey}`;
    const providerKey = `${KV_RATE_PREFIX}provider:${provider}:${windowKey}`;

    // ── Check and increment counters (parallel KV reads) ──────────────────────
    const [ipCountStr, providerCountStr] = await Promise.all([
      c.env.DEDUP_KV.get(ipKey),
      c.env.DEDUP_KV.get(providerKey),
    ]);

    const ipCount = parseInt(ipCountStr ?? '0', 10);
    const providerCount = parseInt(providerCountStr ?? '0', 10);

    if (ipCount >= MAX_REQUESTS_PER_IP) {
      return c.json(
        { error: 'Rate limit exceeded for IP', code: 'RATE_LIMITED' },
        429,
        { 'Retry-After': '60' },
      );
    }

    if (providerCount >= MAX_REQUESTS_PER_PROVIDER) {
      return c.json(
        { error: 'Rate limit exceeded for provider', code: 'RATE_LIMITED' },
        429,
        { 'Retry-After': '60' },
      );
    }

    // ── Increment counters (fire-and-forget, don't block the response) ─────────
    const ttlSeconds = Math.ceil(RATE_WINDOW_MS / 1000) + 5; // window + small buffer
    await Promise.all([
      c.env.DEDUP_KV.put(ipKey, String(ipCount + 1), {
        expirationTtl: ttlSeconds,
      }),
      c.env.DEDUP_KV.put(providerKey, String(providerCount + 1), {
        expirationTtl: ttlSeconds,
      }),
    ]);

    return next();
  };
}
