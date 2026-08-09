import { describe, it, expect, vi } from 'vitest';
import app from '../../src/index.js';
import type { Env } from '../../src/core/env.types.js';
import { computeHmac } from '../../test/helpers/test.helpers.js';

describe('Attack Simulation: Replay Attack (Mismo ID)', () => {
  it('Debe procesar el primer evento y responder 200 silencioso al segundo', async () => {
    const rawBody = JSON.stringify({
      event: { id: 'evt_replay_attack', created_at: Date.now() },
    });
    
    const realSecret = 'whsec_real_secret_123';
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = await computeHmac(realSecret, `${timestamp}.${rawBody}`);

    // Mock KV state
    const kvStore = new Map<string, string>();
    const env: Partial<Env> = {
      ENVIRONMENT: 'test', WOMPI_SECRET: 'wompi_sec', GITHUB_WEBHOOK_SECRET: 'github_sec', EGRESS_SIGNING_SECRET: 'egress_sec',
      STRIPE_WEBHOOK_SECRET: realSecret,
      DEDUP_KV: {
        get: vi.fn().mockImplementation(async (key) => kvStore.get(key) || null),
        put: vi.fn().mockImplementation(async (key, val) => kvStore.set(key, val)),
      } as any,
    };

    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('OK', { status: 200 }));

    const makeRequest = () => app.request('/webhook/stripe', {
      method: 'POST',
      headers: {
        'cf-connecting-ip': '1.2.3.4',
        'Stripe-Signature': `t=${timestamp},v1=${signature}`,
        'Content-Type': 'application/json',
      },
      body: rawBody,
    }, env as Env);

    env.EGRESS_SIGNING_SECRET = 'egress_sec';
    env.ENVIRONMENT = 'development'; // avoid failing if no fetch mock

    const res1 = await makeRequest();
    // Verify it succeeded
    expect(res1.status).toBe(200);

    // Let's just assert that KV got the dedup item
    const keys = Array.from(kvStore.keys());
    expect(keys.some(k => k.startsWith('webhawk:dedup:stripe_'))).toBe(true);
    
    // Clear the spy to isolate the replay request
    fetchSpy.mockClear();

    // Segundo request (Replay Attack)
    const res2 = await makeRequest();
    
    // Debe responder 200 silencioso sin reprocesar (Idempotent response)
    expect(res2.status).toBe(200);
    const json2 = await res2.json() as any;
    expect(json2.message).toBe('Event already processed');
    expect(res2.headers.get('x-webhawk-dedup')).toBe('true');
    
    // Explicitly verify the Replay did NOT reach the downstream service
    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
  });
});
