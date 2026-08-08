/**
 * @file dedup.middleware.ts
 * @description Event deduplication middleware for the WebHawk pipeline.
 *
 * THREAT: Replay Attack (within valid window) — webhook providers legitimately
 * retry deliveries on failure (typically 3–10 retries over hours). An attacker
 * who intercepts a valid webhook and re-sends it within the 5-minute window
 * could trigger duplicate processing (e.g., double crediting an account).
 *
 * DEFENSE:
 * - Store each processed event ID in Cloudflare KV with a TTL of 24 hours.
 * - On each incoming request, check if the event ID was already processed.
 * - If duplicate detected: respond with 2xx SILENTLY — DO NOT return an error.
 *   Reason: if we return 4xx/5xx, the provider interprets it as a delivery failure
 *   and keeps retrying, causing infinite retry loops and exhausting rate limits.
 *
 * EVENT ID RESOLUTION:
 * 1. Use provider-supplied event ID if available (e.g., Wompi event.id, Stripe event.id).
 * 2. Fallback: stable SHA-256 hash of rawBody + key headers (provider-agnostic).
 *
 * KV TTL: 24 hours (86400 seconds) — well beyond the 5-minute replay window,
 * ensures all retry windows of all known providers are covered.
 */

import type { Context, Next } from 'hono';
import type { Env, Variables } from '../env.types.js';

const DEDUP_TTL_SECONDS = 86400; // 24 hours
const KV_PREFIX = 'webhawk:dedup:';

/**
 * Checks if an event ID has been processed before. If yes, returns 200 silently.
 * If no, marks it as processed and continues the pipeline.
 *
 * Depends on `c.get('verificationResult').eventId` set by the HMAC middleware.
 */
export function dedupMiddleware() {
  return async (c: Context<{ Bindings: Env; Variables: Variables }>, next: Next): Promise<Response | void> => {
    const verificationResult = c.get('verificationResult');

    const eventId = verificationResult?.eventId;

    if (!eventId) {
      // No event ID to deduplicate on — proceed normally
      // This should rarely happen given the fallback hash in verifiers
      return next();
    }

    const kvKey = `${KV_PREFIX}${eventId}`;

    // ── Check for duplicate ────────────────────────────────────────────────────
    const existing = await c.env.DEDUP_KV.get(kvKey);

    if (existing !== null) {
      // DUPLICATE DETECTED — respond 200 silently, do NOT propagate
      // This prevents provider retry loops while idempotently handling the event
      return c.json(
        { status: 'ok', message: 'Event already processed' },
        200,
        {
          'X-Webhawk-Dedup': 'true',
        },
      );
    }

    // ── Mark as processed (before forwarding to prevent race on concurrent delivery) ─
    await c.env.DEDUP_KV.put(
      kvKey,
      JSON.stringify({
        processedAt: new Date().toISOString(),
        provider: verificationResult?.provider ?? 'unknown',
      }),
      { expirationTtl: DEDUP_TTL_SECONDS },
    );

    c.set('dedupEventId', eventId);
    return next();
  };
}
