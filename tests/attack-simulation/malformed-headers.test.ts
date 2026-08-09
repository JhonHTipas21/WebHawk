import { describe, it, expect, vi } from 'vitest';
import app from '../../src/index.js';
import type { Env } from '../../src/core/env.types.js';

describe('Attack Simulation: Malformed Headers', () => {
  it('Should reject gracefully without exception on garbage signature headers', async () => {
    const rawBody = JSON.stringify({ event: 'test' });
    
    const env: Partial<Env> = {
      ENVIRONMENT: 'test', WOMPI_SECRET: 'wompi_sec', GITHUB_WEBHOOK_SECRET: 'github_sec', EGRESS_SIGNING_SECRET: 'egress_sec',
      STRIPE_WEBHOOK_SECRET: 'whsec_real_secret_123',
      DEDUP_KV: { get: vi.fn().mockResolvedValue(null), put: vi.fn() } as any,
    };

    // Stripe signature usually looks like t=123,v1=abc
    // Attacker sends malformed string
    const res = await app.request('/webhook/stripe', {
      method: 'POST',
      headers: {
        'cf-connecting-ip': '1.2.3.4',
        'Stripe-Signature': 'just_garbage_string_with_no_t_or_v1',
        'Content-Type': 'application/json',
      },
      body: rawBody,
    }, env as Env);

    // It should handle it gracefully without 500
    expect(res.status).toBe(401);
    const json = await res.json() as any;
    expect(json.code).toBe('MALFORMED_PAYLOAD');
  });

  it('Should reject when signature header is completely missing', async () => {
    const rawBody = JSON.stringify({ event: 'test' });
    
    const env: Partial<Env> = {
      ENVIRONMENT: 'test', WOMPI_SECRET: 'wompi_sec', GITHUB_WEBHOOK_SECRET: 'github_sec', EGRESS_SIGNING_SECRET: 'egress_sec',
      STRIPE_WEBHOOK_SECRET: 'whsec_real_secret_123',
      DEDUP_KV: { get: vi.fn().mockResolvedValue(null), put: vi.fn() } as any,
    };

    const res = await app.request('/webhook/stripe', {
      method: 'POST',
      headers: {
        'cf-connecting-ip': '1.2.3.4',
        'Content-Type': 'application/json',
      },
      body: rawBody,
    }, env as Env);

    expect(res.status).toBe(401);
    const json = await res.json() as any;
    expect(json.code).toBe('MISSING_SIGNATURE');
  });
});
