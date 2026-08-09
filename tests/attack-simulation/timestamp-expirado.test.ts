import { describe, it, expect, vi } from 'vitest';
import app from '../../src/index.js';
import type { Env } from '../../src/core/env.types.js';
import { computeHmac } from '../../test/helpers/test.helpers.js';

describe('Attack Simulation: Timestamp Expirado', () => {
  it('Debe rechazar (401) un request con firma válida pero timestamp antiguo', async () => {
    const rawBody = JSON.stringify({
      event: { id: 'evt_old_123', created_at: Date.now() },
    });
    
    const realSecret = 'whsec_real_secret_123';
    // 10 minutes ago
    const oldTimestamp = Math.floor(Date.now() / 1000) - 600;
    
    // Simulate provider signing with the old timestamp
    const signature = await computeHmac(realSecret, `${oldTimestamp}.${rawBody}`);

    const env: Partial<Env> = {
      ENVIRONMENT: 'test', WOMPI_SECRET: 'wompi_sec', GITHUB_WEBHOOK_SECRET: 'github_sec', EGRESS_SIGNING_SECRET: 'egress_sec',
      STRIPE_WEBHOOK_SECRET: realSecret,
      DEDUP_KV: { get: vi.fn().mockResolvedValue(null), put: vi.fn() } as any,
    };

    const res = await app.request('/webhook/stripe', {
      method: 'POST',
      headers: {
        'cf-connecting-ip': '1.2.3.4',
        'Stripe-Signature': `t=${oldTimestamp},v1=${signature}`,
        'Content-Type': 'application/json',
      },
      body: rawBody,
    }, env as Env);

    // Debe rechazar por timestamp
    expect(res.status).toBe(401);
    const json = await res.json() as any;
    expect(json.code).toBe('EXPIRED_TIMESTAMP');
  });
});
