import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import app from '../../src/index.js';
import type { Env } from '../../src/core/env.types.js';
import { computeHmac } from '../../test/helpers/test.helpers.js';

describe('Attack Simulation: Secret Leakage in Logs', () => {
  let logSpy: any;
  let errSpy: any;

  beforeEach(() => {
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    logSpy.mockRestore();
    errSpy.mockRestore();
  });

  it('Should not leak the HMAC secret or sensitive payload in audit or error logs', async () => {
    const sensitivePayload = 'SENSITIVE_CREDIT_CARD_DATA_9999';
    const rawBody = JSON.stringify({
      event: { id: 'evt_log_test', data: sensitivePayload, created_at: Date.now() },
    });
    
    const realSecret = 'whsec_SUPER_SECRET_HMAC_KEY_DO_NOT_LEAK';
    const timestamp = Math.floor(Date.now() / 1000);
    const validSignature = await computeHmac(realSecret, `${timestamp}.${rawBody}`);

    const env: Partial<Env> = {
      ENVIRONMENT: 'test', WOMPI_SECRET: 'wompi_sec', GITHUB_WEBHOOK_SECRET: 'github_sec',
      STRIPE_WEBHOOK_SECRET: realSecret,
      DEDUP_KV: { get: vi.fn().mockResolvedValue(null), put: vi.fn() } as any,
      EGRESS_SIGNING_SECRET: 'egress_sec',
    };

    // Case 1: Successful Event
    await app.request('/webhook/stripe', {
      method: 'POST',
      headers: {
        'cf-connecting-ip': '1.2.3.4',
        'Stripe-Signature': `t=${timestamp},v1=${validSignature}`,
        'Content-Type': 'application/json',
      },
      body: rawBody,
    }, env as Env);

    // Case 2: Failed Event (Invalid Signature)
    await app.request('/webhook/stripe', {
      method: 'POST',
      headers: {
        'cf-connecting-ip': '1.2.3.4',
        'Stripe-Signature': `t=${Math.floor(Date.now() / 1000)},v1=bad_signature_abc123`,
        'Content-Type': 'application/json',
      },
      body: rawBody,
    }, env as Env);

    // Collect all logged strings
    const allLogs = [
      ...logSpy.mock.calls.flat(),
      ...errSpy.mock.calls.flat(),
    ].map(String).join('\n');

    // Assertion: Secret is NOT in the logs
    expect(allLogs).not.toContain(realSecret);
    
    // Assertion: Sensitive payload is NOT in the logs
    expect(allLogs).not.toContain(sensitivePayload);
  });
});
