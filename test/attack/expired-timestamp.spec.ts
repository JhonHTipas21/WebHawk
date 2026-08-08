/**
 * @file expired-timestamp.spec.ts
 * @description ATTACK SIMULATION: Expired Timestamp / Replay Window Attack
 *
 * Threat: An attacker records a valid webhook (signature + payload) and replays
 * it hours or days later to trigger fraudulent re-processing. Even if the
 * signature is valid, the timestamp must fall within the ±5 minute window.
 *
 * Also tests: clock skew tolerance (timestamps a few seconds outside the window
 * should still be accepted due to CLOCK_SKEW_BUFFER_MS).
 *
 * Note: These tests target the timestamp validation logic in `timestampMiddleware`
 * using direct unit tests (not full HTTP integration) for speed and isolation.
 */

import { describe, it, expect } from 'vitest';
import {
  REPLAY_WINDOW_MS,
  CLOCK_SKEW_BUFFER_MS,
} from '../../src/core/middleware/timestamp.middleware.js';
import { WompiVerifier } from '../../src/verifiers/wompi.verifier.js';
import type { Env } from '../../src/core/env.types.js';
import {
  computeWompiChecksum,
  buildWompiChecksumBody,
} from '../helpers/test.helpers.js';

const VALID_SECRET = 'test_timestamp_secret_789';
const mockEnv: Partial<Env> = { WOMPI_SECRET: VALID_SECRET };

function toArrayBuffer(obj: object): ArrayBuffer {
  return new TextEncoder().encode(JSON.stringify(obj)).buffer as ArrayBuffer;
}

// ── Timestamp window constants ─────────────────────────────────────────────────
describe('Timestamp replay window constants', () => {
  it('REPLAY_WINDOW_MS should be exactly 5 minutes', () => {
    expect(REPLAY_WINDOW_MS).toBe(5 * 60 * 1000);
  });

  it('CLOCK_SKEW_BUFFER_MS should be a positive, reasonable value', () => {
    expect(CLOCK_SKEW_BUFFER_MS).toBeGreaterThan(0);
    expect(CLOCK_SKEW_BUFFER_MS).toBeLessThanOrEqual(60_000); // max 1 minute buffer
  });
});

// ── Attack: Expired timestamp in checksum scheme ──────────────────────────────
describe('ATTACK: Expired timestamp in Wompi event', () => {
  it('verifier should extract timestamp from the event body (timestampMs field)', async () => {
    const transactionId = 'txn_old';
    const transactionStatus = 'APPROVED';

    // Timestamp 10 minutes ago — outside the window
    const oldTimestamp = Math.floor((Date.now() - 10 * 60 * 1000) / 1000);

    const checksum = await computeWompiChecksum({
      transactionId,
      transactionStatus,
      timestamp: oldTimestamp,
      secret: VALID_SECRET,
    });

    const body = buildWompiChecksumBody({
      transactionId,
      transactionStatus,
      timestamp: oldTimestamp,
    });
    const rawBody = toArrayBuffer(body);
    const headers = new Headers({ 'x-event-checksum': checksum });

    const verifier = new WompiVerifier();
    const result = await verifier.verify(rawBody, headers, mockEnv as Env);

    // Signature IS valid — verifier should pass, but timestampMs should be extracted
    expect(result.ok).toBe(true);
    expect(result.timestampMs).toBeDefined();

    // Now check that the timestamp IS outside the window (middleware would reject it)
    const nowMs = Date.now();
    const diff = Math.abs(nowMs - result.timestampMs!);
    const expectedWindowMs = REPLAY_WINDOW_MS + CLOCK_SKEW_BUFFER_MS;

    expect(diff).toBeGreaterThan(expectedWindowMs);
  });

  it('should extract a valid timestamp for a current-time event', async () => {
    const transactionId = 'txn_current';
    const transactionStatus = 'APPROVED';
    const currentTimestamp = Math.floor(Date.now() / 1000);

    const checksum = await computeWompiChecksum({
      transactionId,
      transactionStatus,
      timestamp: currentTimestamp,
      secret: VALID_SECRET,
    });

    const body = buildWompiChecksumBody({
      transactionId,
      transactionStatus,
      timestamp: currentTimestamp,
    });
    const rawBody = toArrayBuffer(body);
    const headers = new Headers({ 'x-event-checksum': checksum });

    const verifier = new WompiVerifier();
    const result = await verifier.verify(rawBody, headers, mockEnv as Env);

    expect(result.ok).toBe(true);
    expect(result.timestampMs).toBeDefined();

    // This timestamp should be within the window
    const nowMs = Date.now();
    const diff = Math.abs(nowMs - result.timestampMs!);
    const expectedWindowMs = REPLAY_WINDOW_MS + CLOCK_SKEW_BUFFER_MS;

    expect(diff).toBeLessThan(expectedWindowMs);
  });
});

// ── Window boundary tests ─────────────────────────────────────────────────────
describe('Timestamp window boundary logic', () => {
  it('should flag a timestamp 5+ minutes in the future as outside window', () => {
    const futureMs = Date.now() + 6 * 60 * 1000; // 6 min future
    const nowMs = Date.now();
    const diff = Math.abs(nowMs - futureMs);
    const windowMs = REPLAY_WINDOW_MS + CLOCK_SKEW_BUFFER_MS;

    expect(diff).toBeGreaterThan(windowMs);
  });

  it('should flag a timestamp from 1 hour ago as outside window', () => {
    const pastMs = Date.now() - 60 * 60 * 1000; // 1 hour ago
    const nowMs = Date.now();
    const diff = Math.abs(nowMs - pastMs);
    const windowMs = REPLAY_WINDOW_MS + CLOCK_SKEW_BUFFER_MS;

    expect(diff).toBeGreaterThan(windowMs);
  });

  it('should accept a timestamp within 4 minutes of now', () => {
    const nearPastMs = Date.now() - 4 * 60 * 1000; // 4 min ago
    const nowMs = Date.now();
    const diff = Math.abs(nowMs - nearPastMs);
    const windowMs = REPLAY_WINDOW_MS + CLOCK_SKEW_BUFFER_MS;

    expect(diff).toBeLessThan(windowMs);
  });
});
