/**
 * @file forwarder.spec.ts
 * @description Unit tests for forwarder webhook logic, including SSRF checks and egress signature generation.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { forwardWebhook } from '../../src/core/forward/forwarder.js';
import { computeHmac } from '../helpers/test.helpers.js';

describe('forwardWebhook core functionality', () => {
  const mockUrl = 'https://api.destination.com/webhook';
  const mockBody = new TextEncoder().encode(JSON.stringify({ event: 'test' })).buffer as ArrayBuffer;
  const mockHeaders = new Headers({
    'content-type': 'application/json',
    'x-request-id': 'req_123',
  });

  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockImplementation(() => {
      return Promise.resolve({
        ok: true,
        status: 200,
      });
    }));
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should successfully forward webhook and pass SSRF validation', async () => {
    const result = await forwardWebhook(mockUrl, mockBody, mockHeaders);
    expect(result.success).toBe(true);
    expect(result.statusCode).toBe(200);
    expect(fetch).toHaveBeenCalled();
  });

  it('should block forwarding to loopback or private ranges due to SSRF validation', async () => {
    const privateUrl = 'https://192.168.1.1/webhook';
    const result = await forwardWebhook(privateUrl, mockBody, mockHeaders);
    expect(result.success).toBe(false);
    expect(result.error).toContain('SSRF guard blocked');
    expect(fetch).not.toHaveBeenCalled();
  });

  it('should attach X-WebHawk-Signature if egress secret is provided', async () => {
    const secret = 'egress_secret_key_123';
    const result = await forwardWebhook(mockUrl, mockBody, mockHeaders, secret);

    expect(result.success).toBe(true);
    expect(fetch).toHaveBeenCalled();

    // Verify the arguments passed to fetch
    const [calledUrl, calledInit] = (fetch as any).mock.calls[0];
    expect(calledUrl).toBe(mockUrl);

    const headers = calledInit.headers as Headers;
    expect(headers.get('x-webhawk-forwarded')).toBe('true');
    expect(headers.get('x-request-id')).toBe('req_123');

    // Parse signature header
    const sigHeader = headers.get('x-webhawk-signature');
    expect(sigHeader).toBeDefined();
    expect(sigHeader).toContain('t=');
    expect(sigHeader).toContain('v1=');

    // Manually verify computed signature
    const parts = Object.fromEntries(
      sigHeader!.split(',').map((p) => {
        const [k, v] = p.split('=');
        return [k, v];
      }),
    );

    const t = parts['t'];
    const v1 = parts['v1'];
    const bodyText = new TextDecoder().decode(mockBody);
    const expectedSig = await computeHmac(secret, `${t}.${bodyText}`);
    expect(v1).toBe(expectedSig);
  });

  it('should not attach X-WebHawk-Signature if egress secret is omitted', async () => {
    await forwardWebhook(mockUrl, mockBody, mockHeaders);
    const [, calledInit] = (fetch as any).mock.calls[0];
    const headers = calledInit.headers as Headers;
    expect(headers.get('x-webhawk-signature')).toBeNull();
  });
});
