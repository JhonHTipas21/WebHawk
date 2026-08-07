/**
 * @file invalid-signature.spec.ts
 * @description ATTACK SIMULATION: Invalid Signature Attack
 *
 * Threat: An attacker sends a webhook with a forged, tampered, or missing
 * HMAC signature. Without proper verification, fraudulent events (e.g., a
 * fake "payment approved" webhook) could be processed as legitimate.
 *
 * This test suite verifies that WompiVerifier rejects all such attempts.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { WompiVerifier } from '../../src/verifiers/wompi.verifier.js';
import type { Env } from '../../src/core/env.types.js';
import {
  computeHmac,
  buildWompiChecksumBody,
  computeWompiChecksum,
} from '../helpers/test.helpers.js';

const VALID_SECRET = 'test_secret_valid_123';
const WRONG_SECRET = 'attacker_wrong_secret_456';
const TEST_TIMESTAMP = Math.floor(Date.now() / 1000); // current timestamp (valid)

const mockEnv: Partial<Env> = {
  WOMPI_SECRET: VALID_SECRET,
  WOMPI_SECRET_PREV: undefined,
};

const verifier = new WompiVerifier();

// ── Helper: build raw body ────────────────────────────────────────────────────
function toArrayBuffer(obj: object): ArrayBuffer {
  return new TextEncoder().encode(JSON.stringify(obj)).buffer as ArrayBuffer;
}

// ── Attack: wompi_hash scheme ─────────────────────────────────────────────────
describe('ATTACK: Invalid wompi_hash signature', () => {
  it('should reject a completely invalid signature', async () => {
    const body = { event: 'transaction.updated', data: {} };
    const rawBody = toArrayBuffer(body);
    const headers = new Headers({ 'wompi_hash': 'not_a_valid_hmac_at_all' });

    const result = await verifier.verify(rawBody, headers, mockEnv as Env);

    expect(result.ok).toBe(false);
    expect(result.reason).toBe('INVALID_SIGNATURE');
    expect(result.provider).toBe('wompi');
  });

  it('should reject a signature computed with the wrong secret', async () => {
    const body = { event: 'transaction.updated', data: { id: 'txn_123' } };
    const rawBody = toArrayBuffer(body);
    const rawBodyBuffer = new TextEncoder().encode(JSON.stringify(body)).buffer as ArrayBuffer;

    // Attacker computes HMAC with THEIR secret, not the valid one
    const attackerHmac = await computeHmac(WRONG_SECRET, rawBodyBuffer);
    const headers = new Headers({ 'wompi_hash': attackerHmac });

    const result = await verifier.verify(rawBody, headers, mockEnv as Env);

    expect(result.ok).toBe(false);
    expect(result.reason).toBe('INVALID_SIGNATURE');
  });

  it('should accept a correctly signed wompi_hash', async () => {
    const body = { event: 'transaction.updated', data: { id: 'txn_valid' } };
    const rawBody = toArrayBuffer(body);
    const validHmac = await computeHmac(VALID_SECRET, rawBody);
    const headers = new Headers({ 'wompi_hash': validHmac });

    const result = await verifier.verify(rawBody, headers, mockEnv as Env);

    expect(result.ok).toBe(true);
    expect(result.provider).toBe('wompi');
  });

  it('should reject if the body was tampered AFTER signing', async () => {
    // Attacker signs the original payload, then modifies the body
    const originalBody = { event: 'transaction.updated', amount: 100 };
    const tamperedBody = { event: 'transaction.updated', amount: 9999999 };

    const originalRaw = toArrayBuffer(originalBody);
    const tamperedRaw = toArrayBuffer(tamperedBody);

    // Signature is valid for originalBody...
    const validHmacForOriginal = await computeHmac(VALID_SECRET, originalRaw);

    // ...but we send it with tamperedBody
    const headers = new Headers({ 'wompi_hash': validHmacForOriginal });

    const result = await verifier.verify(tamperedRaw, headers, mockEnv as Env);

    expect(result.ok).toBe(false);
    expect(result.reason).toBe('INVALID_SIGNATURE');
  });

  it('should reject when signature header is missing', async () => {
    const body = { event: 'transaction.updated' };
    const rawBody = toArrayBuffer(body);
    const headers = new Headers(); // No signature headers

    const result = await verifier.verify(rawBody, headers, mockEnv as Env);

    expect(result.ok).toBe(false);
    expect(result.reason).toBe('MISSING_SIGNATURE');
  });
});

// ── Attack: x-event-checksum scheme ──────────────────────────────────────────
describe('ATTACK: Invalid x-event-checksum signature', () => {
  it('should reject a forged checksum', async () => {
    const body = buildWompiChecksumBody({
      transactionId: 'txn_abc',
      transactionStatus: 'APPROVED',
      timestamp: TEST_TIMESTAMP,
    });
    const rawBody = toArrayBuffer(body);
    const headers = new Headers({
      'x-event-checksum': 'forged_checksum_value_that_is_invalid',
    });

    const result = await verifier.verify(rawBody, headers, mockEnv as Env);

    expect(result.ok).toBe(false);
    expect(result.reason).toBe('INVALID_SIGNATURE');
  });

  it('should reject if transaction status is tampered (e.g., DECLINED → APPROVED)', async () => {
    const transactionId = 'txn_xyz_789';

    // Valid checksum computed for DECLINED status
    const validChecksum = await computeWompiChecksum({
      transactionId,
      transactionStatus: 'DECLINED',
      timestamp: TEST_TIMESTAMP,
      secret: VALID_SECRET,
    });

    // Body has been tampered to APPROVED — checksum no longer matches
    const tamperedBody = buildWompiChecksumBody({
      transactionId,
      transactionStatus: 'APPROVED', // ← tampered
      timestamp: TEST_TIMESTAMP,
    });
    const rawBody = toArrayBuffer(tamperedBody);
    const headers = new Headers({ 'x-event-checksum': validChecksum });

    const result = await verifier.verify(rawBody, headers, mockEnv as Env);

    expect(result.ok).toBe(false);
    expect(result.reason).toBe('INVALID_SIGNATURE');
  });

  it('should accept a correctly computed checksum', async () => {
    const transactionId = 'txn_good';
    const transactionStatus = 'APPROVED';

    const checksum = await computeWompiChecksum({
      transactionId,
      transactionStatus,
      timestamp: TEST_TIMESTAMP,
      secret: VALID_SECRET,
    });

    const body = buildWompiChecksumBody({
      transactionId,
      transactionStatus,
      timestamp: TEST_TIMESTAMP,
    });
    const rawBody = toArrayBuffer(body);
    const headers = new Headers({ 'x-event-checksum': checksum });

    const result = await verifier.verify(rawBody, headers, mockEnv as Env);

    expect(result.ok).toBe(true);
    expect(result.provider).toBe('wompi');
    expect(result.eventId).toBeDefined();
  });
});
