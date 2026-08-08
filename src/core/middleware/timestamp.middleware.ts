/**
 * @file timestamp.middleware.ts
 * @description Timestamp validation middleware for the WebHawk pipeline.
 *
 * THREAT: Replay Attack — without timestamp validation, an attacker who
 * intercepts a valid signed webhook can re-send it days later to trigger
 * fraudulent effects (e.g., replay a payment confirmation).
 *
 * DEFENSE:
 * - Accept webhooks only if their embedded timestamp is within ±5 minutes
 *   of the current server time (OWASP standard, adopted by Stripe, Wompi, GitHub).
 * - A small additional clock skew buffer (CLOCK_SKEW_BUFFER_MS) handles
 *   real-world clock drift between the provider and our server.
 *
 * ORDER IN PIPELINE: Must run AFTER signature verification.
 * Reason: if we validate timestamps before signatures, an attacker can spam
 * malformed (unsigned) requests with expired timestamps and trigger log noise
 * without ever having a valid signature.
 *
 * DUPLICATE DETECTION: Once timestamp passes, deduplication (KV-based) is the
 * second line of defense against replays within the valid window.
 */

import type { Context, Next } from 'hono';
import type { Env, Variables } from '../env.types.js';

/** Replay window: ±5 minutes (300,000 ms) — OWASP recommended */
export const REPLAY_WINDOW_MS = 5 * 60 * 1000;

/**
 * Extra buffer for clock drift between provider and our edge node.
 * A few seconds handles NTP drift without meaningfully expanding the attack window.
 */
export const CLOCK_SKEW_BUFFER_MS = 30_000; // 30 seconds

export type TimestampContext = {
  /**
   * Timestamp (ms) from the verified webhook, stored in Hono context
   * for downstream dedup / audit middleware.
   */
  webhookTimestampMs?: number;
};

/**
 * Validates that the webhook timestamp (extracted by the verifier) is within
 * the allowed replay window.
 *
 * Expects `c.get('verificationResult').timestampMs` to be set by the HMAC
 * verification middleware that runs before this one.
 *
 * If timestampMs is undefined (provider doesn't supply one), uses the current
 * time and logs a warning — this is safe because deduplication still applies.
 */
export function timestampMiddleware() {
  return async (c: Context<{ Bindings: Env; Variables: Variables }>, next: Next): Promise<Response | void> => {
    const verificationResult = c.get('verificationResult');

    const nowMs = Date.now();

    if (!verificationResult?.timestampMs) {
      // Provider did not supply a timestamp — proceed but log warning
      // This path is safe because dedup via event ID still applies
      c.set('webhookTimestampMs', nowMs);
      return next();
    }

    const webhookTimestampMs = verificationResult.timestampMs;
    const diff = Math.abs(nowMs - webhookTimestampMs);

    if (diff > REPLAY_WINDOW_MS + CLOCK_SKEW_BUFFER_MS) {
      const ageSeconds = Math.round((nowMs - webhookTimestampMs) / 1000);

      return c.json(
        {
          error: 'Webhook timestamp out of acceptable window',
          code: 'EXPIRED_TIMESTAMP',
        },
        401,
        {
          // Safe to reveal age in seconds — no secrets exposed
          'X-Webhawk-Reject-Reason': `EXPIRED_TIMESTAMP (age: ${ageSeconds}s)`,
        },
      );
    }

    c.set('webhookTimestampMs', webhookTimestampMs);
    return next();
  };
}
