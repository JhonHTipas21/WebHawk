/**
 * @file hmac.middleware.spec.ts
 * @description Unit tests for HMAC middleware.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Hono } from 'hono';
import { hmacMiddleware } from '../../src/core/middleware/hmac.middleware.js';
import { errorHandler } from '../../src/core/middleware/error-handler.js';
import type { VerifierRegistry } from '../../src/core/verifier.interface.js';

describe('hmacMiddleware', () => {
  let app: Hono<any>;
  let registry: VerifierRegistry<any>;

  beforeEach(() => {
    registry = new Map();
    registry.set('stripe', {
      provider: 'stripe',
      verify: vi.fn().mockResolvedValue({
        ok: true,
        eventId: 'evt_123',
        timestampMs: 1000,
        provider: 'stripe'
      }),
    });

    registry.set('github', {
      provider: 'github',
      verify: vi.fn().mockResolvedValue({
        ok: false,
        reason: 'INVALID_SIGNATURE',
        debugMessage: 'Signature mismatch'
      }),
    });

    app = new Hono<any>();
    app.onError(errorHandler);
    app.post('/:provider', hmacMiddleware(registry), (c) => {
      const result = c.get('verificationResult') as any;
      return c.json({
        eventId: result?.eventId,
        ts: result?.timestampMs
      }, 200);
    });
  });

  it('should verify and pass context for a valid provider request', async () => {
    const res = await app.request('/stripe', {
      method: 'POST',
      body: '{"foo":"bar"}'
    });
    
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.eventId).toBe('evt_123');
    expect(body.ts).toBe(1000);
  });

  it('should block with SignatureVerificationError if verification fails', async () => {
    const res = await app.request('/github', {
      method: 'POST',
      body: '{"foo":"bar"}'
    });
    
    expect(res.status).toBe(401);
    const body = (await res.json()) as any;
    expect(body.code).toBe('INVALID_SIGNATURE');
  });

  it('should throw UnsupportedProviderError for unknown providers', async () => {
    const res = await app.request('/unknown', {
      method: 'POST',
      body: '{"foo":"bar"}'
    });
    
    expect(res.status).toBe(404);
    const body = (await res.json()) as any;
    expect(body.code).toBe('UNSUPPORTED_PROVIDER');
  });
});
