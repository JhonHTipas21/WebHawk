/**
 * @file ip-whitelist.middleware.spec.ts
 * @description Unit tests for IP Whitelist Middleware.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Hono } from 'hono';
import { ipWhitelistMiddleware } from '../../src/core/middleware/ip-whitelist.middleware.js';
import type { VerifierRegistry, WebhookVerifier } from '../../src/core/verifier.interface.js';
import { errorHandler } from '../../src/core/middleware/error-handler.js';

describe('ipWhitelistMiddleware', () => {
  let app: Hono<any>;
  let registry: VerifierRegistry<any>;

  beforeEach(() => {
    registry = new Map<string, WebhookVerifier<any>>();
    
    registry.set('github', {
      provider: 'github',
      allowedIps: ['192.168.1.0/24'],
      verify: vi.fn(),
    });

    registry.set('wompi', {
      provider: 'wompi',
      // No allowedIps configured
      verify: vi.fn(),
    });

    app = new Hono<any>();
    app.onError(errorHandler);
    app.post('/:provider', ipWhitelistMiddleware(registry), (c) => c.text('ok', 200));
  });

  it('should block requests if provider is unknown', async () => {
    const res = await app.request('/unknown-provider', {
      method: 'POST',
      headers: { 'cf-connecting-ip': '192.168.1.50' }
    });
    
    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body).toEqual({
      error: "Provider 'unknown-provider' is not supported",
      code: 'UNSUPPORTED_PROVIDER'
    });
  });

  it('should allow requests if provider has no allowedIps configured', async () => {
    const res = await app.request('/wompi', {
      method: 'POST',
      headers: { 'cf-connecting-ip': '10.0.0.5' }
    });
    
    expect(res.status).toBe(200);
  });

  it('should allow requests if IP matches allowedIps CIDR', async () => {
    const res = await app.request('/github', {
      method: 'POST',
      headers: { 'cf-connecting-ip': '192.168.1.100' }
    });
    
    expect(res.status).toBe(200);
  });

  it('should block requests if IP does not match allowedIps CIDR', async () => {
    const res = await app.request('/github', {
      method: 'POST',
      headers: { 'cf-connecting-ip': '10.5.5.5' }
    });
    
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body).toEqual({
      error: 'IP not allowed',
      code: 'IP_NOT_WHITELISTED'
    });
  });

  it('should block requests if cf-connecting-ip header is missing and allowedIps is configured', async () => {
    const res = await app.request('/github', {
      method: 'POST'
    });
    
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body).toEqual({
      error: 'IP not allowed (missing header)',
      code: 'IP_NOT_WHITELISTED'
    });
  });
});
