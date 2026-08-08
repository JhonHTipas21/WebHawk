/**
 * @file timestamp.middleware.spec.ts
 * @description Unit tests for timestamp validation middleware.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Hono } from 'hono';
import { timestampMiddleware } from '../../src/core/middleware/timestamp.middleware.js';
import { errorHandler } from '../../src/core/middleware/error-handler.js';

describe('timestampMiddleware', () => {
  let app: Hono<any>;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-08-08T12:05:00Z'));

    app = new Hono<any>();
    app.onError(errorHandler);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should pass if timestamp is within tolerance', async () => {
    app.use('*', async (c, next) => {
      c.set('verificationResult', { timestampMs: new Date('2026-08-08T12:03:00Z').getTime() } as any);
      await next();
    });
    app.post('/', timestampMiddleware(), (c) => c.text('ok', 200));

    const res = await app.request('/', { method: 'POST' });
    expect(res.status).toBe(200);
  });

  it('should block with ReplayDetectedError if timestamp is too old', async () => {
    app.use('*', async (c, next) => {
      c.set('verificationResult', { timestampMs: new Date('2026-08-08T11:59:00Z').getTime() } as any); // 6 mins old
      await next();
    });
    app.post('/', timestampMiddleware(), (c) => c.text('ok', 200));

    const res = await app.request('/', { method: 'POST' });
    expect(res.status).toBe(401);
    const body = (await res.json()) as any;
    expect(body.code).toBe('EXPIRED_TIMESTAMP');
  });

  it('should block with ReplayDetectedError if timestamp is too far in future', async () => {
    app.use('*', async (c, next) => {
      c.set('verificationResult', { timestampMs: new Date('2026-08-08T12:11:00Z').getTime() } as any); // 11 mins future
      await next();
    });
    app.post('/', timestampMiddleware(), (c) => c.text('ok', 200));

    const res = await app.request('/', { method: 'POST' });
    expect(res.status).toBe(401);
    const body = (await res.json()) as any;
    expect(body.code).toBe('EXPIRED_TIMESTAMP');
  });

  it('should bypass check if no timestamp is present in context', async () => {
    app.use('*', async (c, next) => {
      c.set('verificationResult', { timestampMs: undefined } as any);
      await next();
    });
    app.post('/', timestampMiddleware(), (c) => c.text('ok', 200));

    const res = await app.request('/', { method: 'POST' });
    expect(res.status).toBe(200);
  });
});
