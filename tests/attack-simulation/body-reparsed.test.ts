import { describe, it, expect, vi } from 'vitest';
import app from '../../src/index.js';
import type { Env } from '../../src/core/env.types.js';
import { computeHmac } from '../../test/helpers/test.helpers.js';

describe('Attack Simulation: Reparsed Body', () => {
  it('Should reject a JSON payload that is semantically identical but modified at the byte level', async () => {
    // Original raw body as the provider signed it
    const originalRawBody = '{"event":"payment","id":"123"}';
    
    // Attacker modifies the spacing (semantically identical JSON, different raw bytes)
    const attackerModifiedBody = '{ "event": "payment", "id": "123" }';
    
    const realSecret = 'whsec_real_secret_123';
    
    // Signature is correctly generated over the ORIGINAL body
    const timestamp = Math.floor(Date.now() / 1000);
    const validSignatureForOriginal = await computeHmac(realSecret, `${timestamp}.${originalRawBody}`);

    const env: Partial<Env> = {
      ENVIRONMENT: 'test', WOMPI_SECRET: 'wompi_sec', GITHUB_WEBHOOK_SECRET: 'github_sec', EGRESS_SIGNING_SECRET: 'egress_sec',
      STRIPE_WEBHOOK_SECRET: realSecret,
      DEDUP_KV: { get: vi.fn().mockResolvedValue(null), put: vi.fn() } as any,
    };

    // We send the ATTACKER MODIFIED body with the ORIGINAL signature
    const res = await app.request('/webhook/stripe', {
      method: 'POST',
      headers: {
        'cf-connecting-ip': '1.2.3.4',
        'Stripe-Signature': `t=${timestamp},v1=${validSignatureForOriginal}`,
        'Content-Type': 'application/json',
      },
      body: attackerModifiedBody,
    }, env as Env);

    // If Webhawk parsed the JSON and validated it over the re-serialized string, this would pass.
    // Since Webhawk uses raw bytes, this MUST fail with 401.
    expect(res.status).toBe(401);
    const json = await res.json() as any;
    expect(json.code).toBe('INVALID_SIGNATURE');
  });
});
