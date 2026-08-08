/**
 * @file index.ts
 * @description WebHawk — Webhook Security Auditor Proxy
 *
 * Cloudflare Workers entry point using Hono framework.
 *
 * Pipeline (ORDER IS NON-NEGOTIABLE per threat model):
 * 1. Rate Limiting (fast, before any crypto work — rejects DoS cheaply)
 * 2. HMAC Verification (captures raw body, runs provider verifier)
 * 3. Timestamp Validation (only after signature — prevents unsigned timestamp spam)
 * 4. Deduplication (rejects replays within valid window, returns 2xx for known events)
 * 5. Audit Logging (logs outcome without secrets or full payload)
 * 6. Forward to destination (with SSRF guard)
 *
 * Multi-provider routing:
 * POST /webhook/:provider — e.g., /webhook/wompi, /webhook/stripe, /webhook/github
 */

import { Hono } from 'hono';
import { AuditLogger } from './core/logger/audit.logger.js';
import { hmacMiddleware } from './core/middleware/hmac.middleware.js';
import { dedupMiddleware } from './core/middleware/dedup.middleware.js';
import { rateLimitMiddleware } from './core/middleware/rate-limit.middleware.js';
import { timestampMiddleware } from './core/middleware/timestamp.middleware.js';
import { forwardWebhook } from './core/forward/forwarder.js';
import { WompiVerifier } from './verifiers/wompi.verifier.js';
import { StripeVerifier } from './verifiers/stripe.verifier.js';
import { GitHubVerifier } from './verifiers/github.verifier.js';
import type { Env } from './core/env.types.js';
import type { VerificationResult, VerifierRegistry } from './core/verifier.interface.js';

import { EnvValidator } from './core/config/env-validator.js';
import { metricsMiddleware } from './core/middleware/metrics.middleware.js';

// ── Verifier Registry (Dependency Inversion) ──────────────────────────────────
// Add new providers here without modifying the pipeline below.
function buildRegistry(): VerifierRegistry<Env> {
  const registry: VerifierRegistry<Env> = new Map();
  registry.set('wompi', new WompiVerifier());
  registry.set('stripe', new StripeVerifier());
  registry.set('github', new GitHubVerifier());
  return registry;
}

const registry = buildRegistry();

type Variables = {
  rawBody: ArrayBuffer;
  verificationResult: VerificationResult;
  webhookTimestampMs: number;
  dedupEventId: string;
};

// ── Hono App ───────────────────────────────────────────────────────────────────
const app = new Hono<{ Bindings: Env; Variables: Variables }>();

// Global configuration validator middleware
app.use('*', async (c, next) => {
  EnvValidator.assert(c.env);
  await next();
});

// Global metrics tracking middleware
app.use('*', metricsMiddleware());

// Health check (no auth required)
app.get('/health', (c) => {
  return c.json({
    status: 'ok',
    service: 'webhawk',
    version: '0.1.0',
    providers: [...registry.keys()],
    timestamp: new Date().toISOString(),
  });
});

import { ipWhitelistMiddleware } from './core/middleware/ip-whitelist.middleware.js';

// ── Webhook Proxy Pipeline ────────────────────────────────────────────────────
app.post(
  '/webhook/:provider',

  // Step 0: IP Whitelist — reject completely unknown/unauthorized IPs early
  ipWhitelistMiddleware(registry),

  // Step 1: Rate limiting — reject DoS early before any crypto
  rateLimitMiddleware(),

  // Step 2: HMAC verification — captures raw body, runs provider verifier
  hmacMiddleware(registry),

  // Step 3: Timestamp validation — only runs if signature is valid
  timestampMiddleware(),

  // Step 4: Deduplication — returns 2xx silently for known events
  dedupMiddleware(),

  // Step 5: Final handler — log success and optionally forward
  async (c) => {
    const result = c.get('verificationResult') as VerificationResult;
    const rawBody = c.get('rawBody') as ArrayBuffer;
    const ip = c.req.header('cf-connecting-ip') ?? 'unknown';
    const cfRay = c.req.header('cf-ray');
    const startTime = Date.now();

    const logger = new AuditLogger(c.env.ENVIRONMENT ?? 'development', c.env.DEDUP_KV);

    logger.logVerified({
      result,
      ip,
      cfRay,
      durationMs: Date.now() - startTime,
    });

    // ── Optional forwarding (if destination URL is configured) ────────────────
    // In a full deployment, the destination URL would come from a KV-stored
    // configuration per provider. For now, we check for a forwarding header
    // (useful in testing and initial deployments).
    const destinationUrl = c.req.header('x-webhawk-forward-to');

    if (destinationUrl) {
      const forwardResult = await forwardWebhook(
        destinationUrl,
        rawBody,
        c.req.raw.headers,
      );

      if (!forwardResult.success) {
        // Log forwarding failure — don't expose details to requester
        console.error(
          JSON.stringify({
            level: 'ERROR',
            event: 'WEBHOOK_FORWARD_FAILED',
            provider: result.provider,
            eventId: result.eventId,
            error: forwardResult.error?.substring(0, 100),
          }),
        );

        // Still return 200 to the provider — their webhook was valid,
        // the forwarding failure is our internal issue, not theirs.
        return c.json(
          {
            status: 'accepted',
            message: 'Webhook verified; forward delivery failed internally',
            eventId: result.eventId,
          },
          202,
        );
      }
    }

    return c.json(
      {
        status: 'ok',
        message: 'Webhook verified and processed',
        eventId: result.eventId,
        provider: result.provider,
      },
      200,
    );
  },
);

// ── 404 fallback ───────────────────────────────────────────────────────────────
app.notFound((c) => {
  return c.json({ error: 'Not found', code: 'NOT_FOUND' }, 404);
});

import { errorHandler } from './core/middleware/error-handler.js';

// ── Global error handler ───────────────────────────────────────────────────────
app.onError(errorHandler);

export default app;
