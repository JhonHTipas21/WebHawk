import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import app from '../../src/index.js';
import type { Env } from '../../src/core/env.types.js';
import { computeHmac } from '../../test/helpers/test.helpers.js';

describe('Attack Simulation: Fuga de Secretos en Logs', () => {
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

  it('No debe filtrar el secreto HMAC ni el payload sensible en los logs de auditoría o errores', async () => {
    const sensitivePayload = 'SENSITIVE_CREDIT_CARD_DATA_9999';
    const rawBody = JSON.stringify({
      event: { id: 'evt_log_test', data: sensitivePayload, created_at: Date.now() },
    });
    
    const realSecret = 'whsec_SUPER_SECRET_HMAC_KEY_DO_NOT_LEAK';
    const timestamp = Math.floor(Date.now() / 1000);
    const validSignature = await computeHmac(realSecret, `${timestamp}.${rawBody}`);

    const env: Partial<Env> = {
      ENVIRONMENT: 'test', WOMPI_SECRET: 'wompi_sec', GITHUB_WEBHOOK_SECRET: 'github_sec', EGRESS_SIGNING_SECRET: 'egress_sec',
      STRIPE_WEBHOOK_SECRET: realSecret,
      DEDUP_KV: { get: vi.fn().mockResolvedValue(null), put: vi.fn() } as any,
      EGRESS_SIGNING_SECRET: 'egress_sec',
    };

    // Caso 1: Evento Exitoso
    await app.request('/webhook/stripe', {
      method: 'POST',
      headers: {
        'cf-connecting-ip': '1.2.3.4',
        'Stripe-Signature': `t=${timestamp},v1=${validSignature}`,
        'Content-Type': 'application/json',
      },
      body: rawBody,
    }, env as Env);

    // Caso 2: Evento Fallido (Firma Inválida)
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
