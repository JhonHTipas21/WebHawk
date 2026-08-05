/**
 * @file hmac.middleware.ts
 * @description HMAC verification middleware — entry point of the WebHawk pipeline.
 *
 * Responsibilities:
 * 1. Capture the raw request body as ArrayBuffer (BEFORE any JSON parsing).
 * 2. Route to the correct WebhookVerifier based on the `provider` path param.
 * 3. Run verify() and short-circuit with 401 if verification fails.
 * 4. Attach VerificationResult to context for downstream middleware.
 *
 * CRITICAL ORDER:
 * This middleware MUST be first in the pipeline. Any earlier middleware
 * that reads the body (e.g., a JSON parser) would consume the stream and
 * make rawBody unavailable, or worse, break the HMAC by hashing re-parsed JSON.
 *
 * BODY CAPTURE:
 * We use c.req.arrayBuffer() which reads the body ONCE as raw bytes.
 * We store it in context for potential downstream use (forwarding).
 * Hono's `c.req.arrayBuffer()` is safe to call before any body parsers.
 */

import type { Context, Next } from 'hono';
import type { Env } from '../env.types.js';
import type { VerificationResult, VerifierRegistry } from '../verifier.interface.js';

/**
 * Factory that creates the HMAC verification middleware for a given verifier registry.
 *
 * @param registry - Map of provider name → WebhookVerifier. Passed as a dependency
 *                   (Dependency Inversion Principle) — the middleware is decoupled
 *                   from any specific verifier implementation.
 */
export function hmacMiddleware(registry: VerifierRegistry<Env>) {
  return async (c: Context<{ Bindings: Env }>, next: Next): Promise<Response | void> => {
    // ── 1. Capture raw body BEFORE any parsing ────────────────────────────────
    const rawBody = await c.req.arrayBuffer();
    c.set('rawBody', rawBody);

    // ── 2. Resolve provider from path ─────────────────────────────────────────
    const provider = c.req.param('provider');

    if (!provider) {
      return c.json(
        { error: 'Missing provider in path', code: 'UNSUPPORTED_PROVIDER' },
        400,
      );
    }

    const verifier = registry.get(provider);

    if (!verifier) {
      return c.json(
        {
          error: `No verifier registered for provider: ${provider}`,
          code: 'UNSUPPORTED_PROVIDER',
        },
        404,
      );
    }

    // ── 3. Run HMAC verification ───────────────────────────────────────────────
    let result: VerificationResult;

    try {
      result = await verifier.verify(rawBody, c.req.raw.headers, c.env);
    } catch (err: unknown) {
      // Catch unexpected errors from verifier — never let crypto errors
      // bubble as 500 (could leak internal details)
      const msg = err instanceof Error ? err.message : 'Unknown error';
      return c.json(
        {
          error: 'Internal verification error',
          code: 'INVALID_SIGNATURE',
          // Safe: no secrets in error message
          hint: msg.substring(0, 100),
        },
        401,
      );
    }

    if (!result.ok) {
      // Log verification failure metadata (no secrets, no full payload)
      console.error(
        JSON.stringify({
          level: 'WARN',
          event: 'WEBHOOK_VERIFICATION_FAILED',
          provider: result.provider,
          reason: result.reason,
          debugMessage: result.debugMessage,
          timestamp: new Date().toISOString(),
        }),
      );

      return c.json(
        { error: 'Webhook signature verification failed', code: result.reason },
        401,
      );
    }

    // ── 4. Attach result to context for downstream middleware ─────────────────
    c.set('verificationResult', result);
    return next();
  };
}
