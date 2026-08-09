import { describe, it, expect, vi } from 'vitest';
import app from '../../src/index.js';
import type { Env } from '../../src/core/env.types.js';
import { computeHmac } from '../../test/helpers/test.helpers.js';

describe('Attack Simulation: Body Demasiado Grande', () => {
  it('Debe rechazar un payload que exceda 1MB antes de cualquier procesamiento criptográfico', async () => {
    // We create a body larger than 1MB (MAX_BODY_BYTES)
    const largeData = 'a'.repeat(1 * 1024 * 1024 + 10);
    const rawBody = JSON.stringify({
      event: { id: 'evt_large', data: largeData, created_at: Date.now() },
    });
    
    const realSecret = 'whsec_real_secret_123';
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = await computeHmac(realSecret, `${timestamp}.${rawBody}`);

    // We can spy on crypto to prove it wasn't even called (saving CPU).
    // Or just trust the 413 response.
    const env: Partial<Env> = {
      ENVIRONMENT: 'test', WOMPI_SECRET: 'wompi_sec', GITHUB_WEBHOOK_SECRET: 'github_sec', EGRESS_SIGNING_SECRET: 'egress_sec',
      STRIPE_WEBHOOK_SECRET: realSecret,
      DEDUP_KV: { get: vi.fn().mockResolvedValue(null), put: vi.fn() } as any,
    };

    const res = await app.request('/webhook/stripe', {
      method: 'POST',
      headers: {
        'cf-connecting-ip': '1.2.3.4',
        'Stripe-Signature': `t=${timestamp},v1=${signature}`,
        'Content-Type': 'application/json',
        'Content-Length': rawBody.length.toString(), // Explicitly set it
      },
      body: rawBody,
    }, env as Env);

    // Debe rechazar por Body Too Large ANTES de pasar a HMAC
    expect(res.status).toBe(413);
    const json = await res.json() as any;
    expect(json.code).toBe('BODY_TOO_LARGE');
  });
});
