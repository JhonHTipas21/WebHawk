import { describe, it, expect, vi } from 'vitest';
import app from '../../src/index.js';
import type { Env } from '../../src/core/env.types.js';
import { computeHmac } from '../../test/helpers/test.helpers.js';
import { SsrfGuard } from '../../src/core/forward/ssrf.guard.js';

describe('Attack Simulation: SSRF (Server-Side Request Forgery)', () => {
  it('Should block forwarding attempts to loopback, AWS metadata, and private IPs', async () => {
    // This attack requires a valid webhook that attempts to exploit the forwarder 
    // using the 'x-webhawk-forward-to' header.
    
    const rawBody = JSON.stringify({ event: 'test' });
    const realSecret = 'whsec_real_secret_123';
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = await computeHmac(realSecret, `${timestamp}.${rawBody}`);

    const env: Partial<Env> = {
      ENVIRONMENT: 'test', WOMPI_SECRET: 'wompi_sec', GITHUB_WEBHOOK_SECRET: 'github_sec', EGRESS_SIGNING_SECRET: 'egress_sec',
      STRIPE_WEBHOOK_SECRET: realSecret,
      DEDUP_KV: { get: vi.fn().mockResolvedValue(null), put: vi.fn() } as any,
    };

    // Helper to test a payload against the app
    const runSsrfAttack = async (targetUrl: string) => {
      // Rather than running full fetch (which we don't mock here and might leak),
      // we check that Webhawk catches it internally via the SSRF guard and fails the forward.
      // Wait, the SSRF guard is inside forwardWebhook. We can directly test the guard 
      // or see if the app returns the 202 failure code for internal forward error.
      const res = await app.request('/webhook/stripe', {
        method: 'POST',
        headers: {
          'cf-connecting-ip': '1.2.3.4',
          'Stripe-Signature': `t=${timestamp},v1=${signature}`,
          'Content-Type': 'application/json',
          'x-webhawk-forward-to': targetUrl,
        },
        body: rawBody,
      }, env as Env);
      
      // The proxy processes it, but fails the forward securely.
      // Expecting 202 (Accepted, but forward failed) instead of actually hitting the network.
      expect(res.status).toBe(202);
      const json = await res.json() as any;
      expect(json.message).toContain('failed');
    };

    // Localhost
    await runSsrfAttack('https://localhost/api/internal');
    // AWS Meta-data
    await runSsrfAttack('https://169.254.169.254/latest/meta-data/');
    // Private Subnet
    await runSsrfAttack('https://10.0.0.1/admin');
  });

  it('SsrfGuard statically prohibits insecure connections', () => {
    const guard = new SsrfGuard();
    
    // Explicit static tests as required by AppSec rules
    expect(guard.validate('http://169.254.169.254/').safe).toBe(false);
    expect(guard.validate('https://127.0.0.1:22/').safe).toBe(false); // No ssh port
    expect(guard.validate('ftp://internal-server/').safe).toBe(false); // No ftp scheme
  });
});
