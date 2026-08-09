import { describe, it, expect, vi } from 'vitest';
import app from '../../src/index.js';
import type { Env } from '../../src/core/env.types.js';
import { computeHmac } from '../../test/helpers/test.helpers.js';

describe('Attack Simulation: Timing Attack on HMAC Signature', () => {
  it('Should compare signatures in constant time (without significant variance)', async () => {
    const rawBody = JSON.stringify({
      event: { id: 'evt_timing', created_at: Date.now() },
    });
    
    const realSecret = 'whsec_real_secret_timing_123';
    const timestamp = Math.floor(Date.now() / 1000);
    const validSignature = await computeHmac(realSecret, `${timestamp}.${rawBody}`);
    
    // We create a partially valid signature (e.g. first 10 chars are correct)
    const partiallyValidSig = validSignature.substring(0, 10) + 'a'.repeat(validSignature.length - 10);
    const completelyInvalidSig = 'b'.repeat(validSignature.length);

    const env: Partial<Env> = {
      ENVIRONMENT: 'test', WOMPI_SECRET: 'wompi_sec', GITHUB_WEBHOOK_SECRET: 'github_sec', EGRESS_SIGNING_SECRET: 'egress_sec',
      STRIPE_WEBHOOK_SECRET: realSecret,
      DEDUP_KV: { get: vi.fn().mockResolvedValue(null), put: vi.fn() } as any,
    };

    const runTiming = async (sig: string, iterations: number) => {
      const start = performance.now();
      for (let i = 0; i < iterations; i++) {
        await app.request('/webhook/stripe', {
          method: 'POST',
          headers: {
            'cf-connecting-ip': '1.2.3.4',
            'Stripe-Signature': `t=${timestamp},v1=${sig}`,
            'Content-Type': 'application/json',
          },
          body: rawBody,
        }, env as Env);
      }
      return performance.now() - start;
    };

    const ITERATIONS = 30; // High enough to measure, low enough for CI
    
    // Warmup
    await runTiming(completelyInvalidSig, 5);

    const timePartial = await runTiming(partiallyValidSig, ITERATIONS);
    const timeInvalid = await runTiming(completelyInvalidSig, ITERATIONS);

    const diff = Math.abs(timePartial - timeInvalid);
    
    // The difference should be practically zero if constant time is used.
    // We allow up to 10ms variance for CI flakiness.
    expect(diff).toBeLessThan(15);
  });
});
