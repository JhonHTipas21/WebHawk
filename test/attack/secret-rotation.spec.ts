/**
 * @file secret-rotation.spec.ts
 * @description ATTACK SIMULATION: Secret Rotation Edge Cases
 *
 * Threat: If secret rotation is not handled with an overlap window,
 * any "in-flight" webhooks signed with the old secret will be rejected
 * after the rotation. Providers may not retry these, causing missed events.
 *
 * Conversely, if the overlap window is too long or never cleaned up,
 * a compromised old secret remains valid as an attack vector.
 *
 * These tests verify that both current and previous secrets are accepted
 * during the overlap window, and that a completely invalid secret is rejected.
 */

import { describe, it, expect } from 'vitest';
import { WompiVerifier } from '../../src/verifiers/wompi.verifier.js';
import type { Env } from '../../src/core/env.types.js';
import { computeHmac } from '../helpers/test.helpers.js';

const CURRENT_SECRET = 'new_rotated_secret_2024';
const PREVIOUS_SECRET = 'old_secret_before_rotation';
const EXPIRED_SECRET = 'very_old_secret_no_longer_valid';

function toArrayBuffer(obj: object): ArrayBuffer {
  return new TextEncoder().encode(JSON.stringify(obj)).buffer as ArrayBuffer;
}

const verifier = new WompiVerifier();

describe('Secret Rotation — Overlap Window', () => {
  it('should accept webhook signed with CURRENT secret', async () => {
    const body = { event: 'transaction.updated', data: { id: 'txn_001' } };
    const rawBody = toArrayBuffer(body);
    const hmac = await computeHmac(CURRENT_SECRET, rawBody);
    const headers = new Headers({ 'wompi_hash': hmac });

    const env: Partial<Env> = {
      WOMPI_SECRET: CURRENT_SECRET,
      WOMPI_SECRET_PREV: PREVIOUS_SECRET,
    };

    const result = await verifier.verify(rawBody, headers, env as Env);
    expect(result.ok).toBe(true);
  });

  it('should accept webhook signed with PREVIOUS secret during overlap window', async () => {
    // This simulates a webhook that was signed with the old secret and is
    // "in flight" during a rotation — it must still be accepted.
    const body = { event: 'transaction.updated', data: { id: 'txn_in_flight' } };
    const rawBody = toArrayBuffer(body);
    const hmac = await computeHmac(PREVIOUS_SECRET, rawBody);
    const headers = new Headers({ 'wompi_hash': hmac });

    const env: Partial<Env> = {
      WOMPI_SECRET: CURRENT_SECRET,
      WOMPI_SECRET_PREV: PREVIOUS_SECRET,
    };

    const result = await verifier.verify(rawBody, headers, env as Env);
    expect(result.ok).toBe(true);
  });

  it('should reject webhook signed with an expired secret (not in rotation)', async () => {
    // Once the old secret is removed from WOMPI_SECRET_PREV, it must be rejected
    const body = { event: 'transaction.updated', data: { id: 'txn_expired' } };
    const rawBody = toArrayBuffer(body);
    const hmac = await computeHmac(EXPIRED_SECRET, rawBody);
    const headers = new Headers({ 'wompi_hash': hmac });

    const env: Partial<Env> = {
      WOMPI_SECRET: CURRENT_SECRET,
      WOMPI_SECRET_PREV: PREVIOUS_SECRET,
      // EXPIRED_SECRET is not in either slot
    };

    const result = await verifier.verify(rawBody, headers, env as Env);
    expect(result.ok).toBe(false);
    expect(result.reason).toBe('INVALID_SIGNATURE');
  });

  it('should work correctly with only one secret (no rotation active)', async () => {
    const body = { event: 'transaction.updated', data: { id: 'txn_no_rotation' } };
    const rawBody = toArrayBuffer(body);
    const hmac = await computeHmac(CURRENT_SECRET, rawBody);
    const headers = new Headers({ 'wompi_hash': hmac });

    const env: Partial<Env> = {
      WOMPI_SECRET: CURRENT_SECRET,
      WOMPI_SECRET_PREV: undefined, // No rotation active
    };

    const result = await verifier.verify(rawBody, headers, env as Env);
    expect(result.ok).toBe(true);
  });

  it('should not double-try same secret when current === previous', async () => {
    // Edge case: if someone accidentally sets PREV = CURRENT, we should still work correctly
    const body = { event: 'transaction.updated', data: { id: 'txn_same_secret' } };
    const rawBody = toArrayBuffer(body);
    const hmac = await computeHmac(CURRENT_SECRET, rawBody);
    const headers = new Headers({ 'wompi_hash': hmac });

    const env: Partial<Env> = {
      WOMPI_SECRET: CURRENT_SECRET,
      WOMPI_SECRET_PREV: CURRENT_SECRET, // Same as current
    };

    const result = await verifier.verify(rawBody, headers, env as Env);
    expect(result.ok).toBe(true);
  });
});
