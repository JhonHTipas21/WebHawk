/**
 * @file dedup.middleware.spec.ts
 * @description Unit tests for deduplication middleware.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Hono } from 'hono';
import { dedupMiddleware } from '../../src/core/middleware/dedup.middleware.js';
import { errorHandler } from '../../src/core/middleware/error-handler.js';

describe('dedupMiddleware', () => {
  let app: Hono<any>;
  let kv: any;

  beforeEach(() => {
    kv = {
      get: vi.fn().mockResolvedValue(null),
      put: vi.fn().mockResolvedValue(undefined),
    };

    app = new Hono<any>();
    app.onError(errorHandler);
    app.use('*', async (c, next) => {
      c.env = { DEDUP_KV: kv };
      c.set('verificationResult', { eventId: 'test-event-123' } as any);
      await next();
    });
    app.post('/:provider', dedupMiddleware(), (c) => c.text('processed', 200));
  });

  it('should process new events and store them in KV', async () => {
    const res = await app.request('/stripe', { method: 'POST' });
    
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).toBe('processed');
    
    expect(kv.get).toHaveBeenCalledWith('webhawk:dedup:test-event-123');
    expect(kv.put).toHaveBeenCalledWith('webhawk:dedup:test-event-123', expect.any(String), expect.any(Object));
  });

  it('should return 200 with dedup header for already seen events without processing', async () => {
    kv.get.mockResolvedValue('processed');

    const res = await app.request('/stripe', { method: 'POST' });
    
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.status).toBe('ok');
    expect(body.message).toBe('Event already processed');
    expect(res.headers.get('x-webhawk-dedup')).toBe('true');
    
    expect(kv.put).not.toHaveBeenCalled();
  });

  it('should bypass dedup if no eventId is set in context', async () => {
    app = new Hono<any>();
    app.use('*', async (c, next) => {
      c.env = { DEDUP_KV: kv };
      // No dedupEventId set
      await next();
    });
    app.post('/:provider', dedupMiddleware(), (c) => c.text('processed', 200));

    const res = await app.request('/github', { method: 'POST' });
    expect(res.status).toBe(200);
    expect(kv.get).not.toHaveBeenCalled();
    expect(kv.put).not.toHaveBeenCalled();
  });
});
