/**
 * @file metrics.middleware.spec.ts
 * @description Unit tests for metrics middleware.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Hono } from 'hono';
import { metricsMiddleware } from '../../src/core/middleware/metrics.middleware.js';
import { MetricsTracker } from '../../src/core/metrics/metrics-tracker.js';

describe('metricsMiddleware', () => {
  let app: Hono<any>;
  let kv: any;

  beforeEach(() => {
    vi.spyOn(MetricsTracker, 'increment').mockResolvedValue(undefined);
    kv = {};
    app = new Hono<any>();
    
    app.use('*', async (c, next) => {
      c.env = { DEDUP_KV: kv };
      await next();
    });
    app.use('*', metricsMiddleware());
  });

  it('should map 200 status to verified', async () => {
    app.post('/:provider', (c) => c.text('ok', 200));

    const res = await app.request('/stripe', { method: 'POST' });
    expect(res.status).toBe(200);

    expect(MetricsTracker.increment).toHaveBeenCalledWith(
      kv,
      'stripe',
      'verified',
      expect.any(Number)
    );
  });

  it('should map 429 status to rateLimited', async () => {
    app.post('/:provider', (c) => c.text('rate limited', 429));

    const res = await app.request('/github', { method: 'POST' });
    expect(res.status).toBe(429);

    expect(MetricsTracker.increment).toHaveBeenCalledWith(
      kv,
      'github',
      'rateLimited',
      expect.any(Number)
    );
  });

  it('should map 401 status to rejected', async () => {
    app.post('/:provider', (c) => c.text('unauthorized', 401));

    const res = await app.request('/wompi', { method: 'POST' });
    expect(res.status).toBe(401);

    expect(MetricsTracker.increment).toHaveBeenCalledWith(
      kv,
      'wompi',
      'rejected',
      expect.any(Number)
    );
  });

  it('should map 200 status with x-webhawk-dedup header to duplicate', async () => {
    app.post('/:provider', (c) => {
      c.header('x-webhawk-dedup', 'true');
      return c.text('duplicate', 200);
    });

    const res = await app.request('/stripe', { method: 'POST' });
    expect(res.status).toBe(200);

    expect(MetricsTracker.increment).toHaveBeenCalledWith(
      kv,
      'stripe',
      'duplicate',
      expect.any(Number)
    );
  });

  it('should fall back to verified for other statuses', async () => {
    app.post('/:provider', (c) => c.text('internal error', 500));

    const res = await app.request('/stripe', { method: 'POST' });
    expect(res.status).toBe(500);

    expect(MetricsTracker.increment).toHaveBeenCalledWith(
      kv,
      'stripe',
      'verified',
      expect.any(Number)
    );
  });
});
