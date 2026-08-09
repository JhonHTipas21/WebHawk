import { describe, it, expect, vi } from 'vitest';
import app from '../../src/index.js';
import type { Env } from '../../src/core/env.types.js';

describe('Attack Simulation: Rate Limit Bypass', () => {
  it('Debe rechazar (429) tras exceder el límite de peticiones (Rate Limit)', async () => {
    // The IP limit is 60 requests.
    const MAX_REQUESTS = 60;
    
    // We mock the KV store to easily simulate hitting the limit without 60 actual requests.
    // The middleware gets the IP count and Provider count.
    const mockKv = {
      get: vi.fn().mockImplementation(async (key: string) => {
        if (key.includes('ip:1.2.3.4')) {
          return String(MAX_REQUESTS); // tell the middleware we already hit the limit
        }
        return '0';
      }),
      put: vi.fn(),
    };

    const env: Partial<Env> = {
      ENVIRONMENT: 'test', WOMPI_SECRET: 'wompi_sec', GITHUB_WEBHOOK_SECRET: 'github_sec', EGRESS_SIGNING_SECRET: 'egress_sec',
      STRIPE_WEBHOOK_SECRET: 'whsec_real_secret_123',
      DEDUP_KV: mockKv as any,
    };

    const res = await app.request('/webhook/stripe', {
      method: 'POST',
      headers: {
        'cf-connecting-ip': '1.2.3.4', // Matches the mock key
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({}),
    }, env as Env);

    // It should hit the rate limit and return 429
    expect(res.status).toBe(429);
    const json = await res.json() as any;
    expect(json.code).toBe('RATE_LIMITED');
  });
});
