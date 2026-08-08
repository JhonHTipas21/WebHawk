/**
 * @file metrics.middleware.ts
 * @description Request metrics middleware for the WebHawk pipeline.
 *
 * Intercepts each request after it completes to record outcome metrics
 * using MetricsTracker. Runs as a post-processing step, recording duration
 * and outcome (verified/rejected/duplicate/rate-limited) in Cloudflare KV.
 *
 * This middleware is position-independent within the pipeline and should be
 * applied as a global 'use' middleware so it wraps all routes.
 */

import type { Context, Next } from 'hono';
import type { Env, Variables } from '../env.types.js';
import { MetricsTracker } from '../metrics/metrics-tracker.js';

export function metricsMiddleware() {
  return async (c: Context<{ Bindings: Env; Variables: Variables }>, next: Next): Promise<void> => {
    const startMs = Date.now();

    await next();

    const durationMs = Date.now() - startMs;
    const provider = c.req.param('provider') ?? 'unknown';
    const status = c.res.status;

    // Map HTTP status to metric field
    let field: 'verified' | 'rejected' | 'duplicate' | 'rateLimited';

    if (status === 429) {
      field = 'rateLimited';
    } else if (status === 401) {
      field = 'rejected';
    } else if (status === 200 && c.res.headers.get('x-webhawk-dedup') === 'true') {
      field = 'duplicate';
    } else {
      field = 'verified';
    }

    // Fire-and-forget — do not await, metrics must not affect response latency
    MetricsTracker.increment(c.env.DEDUP_KV, provider, field, durationMs).catch((err) => {
      console.warn(
        JSON.stringify({
          level: 'WARN',
          event: 'METRICS_WRITE_FAILED',
          provider,
          error: err instanceof Error ? err.message.substring(0, 100) : 'unknown',
        }),
      );
    });
  };
}
