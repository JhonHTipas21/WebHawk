import { describe, it, expect, vi } from 'vitest';
import app from '../../src/index.js';
import type { Env } from '../../src/core/env.types.js';
import { computeHmac } from '../../test/helpers/test.helpers.js';

describe('Attack Simulation: Firma Inválida', () => {
  it('Debe rechazar (401) un request con firma HMAC incorrecta', async () => {
    const rawBody = JSON.stringify({
      event: { id: 'evt_123', created_at: Date.now() },
    });
    
    const timestamp = Math.floor(Date.now() / 1000);
    const attackerSignature = await computeHmac('wrong_secret', `${timestamp}.${rawBody}`);

    const env: Partial<Env> = {
      ENVIRONMENT: 'test', WOMPI_SECRET: 'wompi_sec', GITHUB_WEBHOOK_SECRET: 'github_sec', EGRESS_SIGNING_SECRET: 'egress_sec',
      STRIPE_WEBHOOK_SECRET: 'whsec_real_secret_123',
      DEDUP_KV: { get: vi.fn().mockResolvedValue(null), put: vi.fn() } as any,
    };

    const res = await app.request('/webhook/stripe', {
      method: 'POST',
      headers: {
        'cf-connecting-ip': '1.2.3.4', // Valid IP for rate-limiting
        'Stripe-Signature': `t=${timestamp},v1=${attackerSignature}`,
        'Content-Type': 'application/json',
      },
      body: rawBody,
    }, env as Env);

    // The attack must be rejected
    expect(res.status).toBe(401);
    const json = await res.json() as any;
    expect(json.code).toBe('INVALID_SIGNATURE');
  });
});
