/**
 * @file rate-limit.middleware.spec.ts
 * @description Unit tests for rate limiting middleware.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Hono } from 'hono';
import { rateLimitMiddleware } from '../../src/core/middleware/rate-limit.middleware.js';
import { errorHandler } from '../../src/core/middleware/error-handler.js';

describe('rateLimitMiddleware', () => {
  let app: Hono<any>;
  let kv: any;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-08-08T12:00:00Z'));

    kv = {
      get: vi.fn().mockResolvedValue(null),
      put: vi.fn().mockResolvedValue(undefined),
    };

    app = new Hono<any>();
    app.onError(errorHandler);
    app.use('*', async (c, next) => {
      c.env = { DEDUP_KV: kv };
      await next();
    });
    app.post('/:provider', rateLimitMiddleware(), (c) => c.text('ok', 200));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should allow requests below the limit', async () => {
    const res = await app.request('/stripe', {
      method: 'POST',
      headers: { 'cf-connecting-ip': '1.1.1.1' }
    });
    
    expect(res.status).toBe(200);
    expect(kv.get).toHaveBeenCalledWith('webhawk:rate:ip:1.1.1.1:29769840');
    expect(kv.put).toHaveBeenCalledWith('webhawk:rate:ip:1.1.1.1:29769840', '1', expect.any(Object));
  });

  it('should block requests above the limit', async () => {
    kv.get.mockImplementation(async (key: string) => {
      if (key.includes('ip:')) return '60'; // MAX_REQUESTS_PER_IP
      return '0';
    });

    const res = await app.request('/stripe', {
      method: 'POST',
      headers: { 'cf-connecting-ip': '1.1.1.1' }
    });
    
    expect(res.status).toBe(429);
    const body = (await res.json()) as any;
    expect(body.code).toBe('RATE_LIMITED');
    expect(kv.put).not.toHaveBeenCalled();
  });

  it('should use unknown IP if cf-connecting-ip is missing', async () => {
    await app.request('/github', { method: 'POST' });
    expect(kv.get).toHaveBeenCalledWith('webhawk:rate:ip:unknown:29769840');
  });
});
