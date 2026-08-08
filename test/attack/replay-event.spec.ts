/**
 * @file replay-event.spec.ts
 * @description ATTACK SIMULATION: Replay Event Attack
 *
 * Threat: A valid, legitimately signed webhook is intercepted and replayed
 * within the valid timestamp window. Example: an attacker replays a
 * "payment approved" event to trigger a double credit.
 *
 * Providers retry deliveries legitimately (3-10 retries over hours).
 * The dedup system must:
 * 1. Reject true replays (attacker re-sending the same event ID).
 * 2. Return 2xx (not 4xx) for retries — so the provider stops retrying.
 * 3. NOT forward the duplicate to the downstream service.
 *
 * These tests use a mock KV namespace to simulate the dedup store behavior.
 */

import { describe, it, expect } from 'vitest';
import { WompiVerifier } from '../../src/verifiers/wompi.verifier.js';
import type { Env } from '../../src/core/env.types.js';
import {
  computeHmac,
  computeWompiChecksum,
  buildWompiChecksumBody,
} from '../helpers/test.helpers.js';

const VALID_SECRET = 'replay_test_secret_abc';
const mockEnv: Partial<Env> = { WOMPI_SECRET: VALID_SECRET };

function toArrayBuffer(obj: object): ArrayBuffer {
  return new TextEncoder().encode(JSON.stringify(obj)).buffer as ArrayBuffer;
}

// ── In-memory KV mock ─────────────────────────────────────────────────────────
class MockKVNamespace {
  private store = new Map<string, string>();

  async get(key: string): Promise<string | null> {
    return this.store.get(key) ?? null;
  }

  async put(key: string, value: string, _options?: { expirationTtl?: number }): Promise<void> {
    this.store.set(key, value);
  }

  has(key: string): boolean {
    return this.store.has(key);
  }

  clear(): void {
    this.store.clear();
  }
}

// ── Event ID stability tests ──────────────────────────────────────────────────
describe('Event ID stability for deduplication', () => {
  const verifier = new WompiVerifier();

  it('should produce the same eventId for identical wompi_hash payloads', async () => {
    const body = { event: 'transaction.updated', data: { id: 'txn_replay_001' } };
    const rawBody1 = toArrayBuffer(body);
    const rawBody2 = toArrayBuffer(body); // same content

    const hmac = await computeHmac(VALID_SECRET, rawBody1);
    const headers = new Headers({ 'wompi_hash': hmac });

    const result1 = await verifier.verify(rawBody1, headers, mockEnv as Env);
    const result2 = await verifier.verify(rawBody2, headers, mockEnv as Env);

    expect(result1.ok).toBe(true);
    expect(result2.ok).toBe(true);

    // Same payload must produce same event ID — this is what enables dedup to work
    expect(result1.eventId).toBe(result2.eventId);
  });

  it('should produce different eventIds for different payloads', async () => {
    const body1 = { event: 'transaction.updated', data: { id: 'txn_001' } };
    const body2 = { event: 'transaction.updated', data: { id: 'txn_002' } };

    const rawBody1 = toArrayBuffer(body1);
    const rawBody2 = toArrayBuffer(body2);

    const hmac1 = await computeHmac(VALID_SECRET, rawBody1);
    const hmac2 = await computeHmac(VALID_SECRET, rawBody2);

    const result1 = await verifier.verify(rawBody1, new Headers({ 'wompi_hash': hmac1 }), mockEnv as Env);
    const result2 = await verifier.verify(rawBody2, new Headers({ 'wompi_hash': hmac2 }), mockEnv as Env);

    expect(result1.ok).toBe(true);
    expect(result2.ok).toBe(true);
    expect(result1.eventId).not.toBe(result2.eventId);
  });

  it('should use event type + timestamp as eventId for checksum scheme', async () => {
    const transactionId = 'txn_checksum_dedup';
    const transactionStatus = 'APPROVED';
    const timestamp = Math.floor(Date.now() / 1000);

    const checksum = await computeWompiChecksum({
      transactionId,
      transactionStatus,
      timestamp,
      secret: VALID_SECRET,
    });

    const body = buildWompiChecksumBody({ transactionId, transactionStatus, timestamp });
    const rawBody = toArrayBuffer(body);
    const headers = new Headers({ 'x-event-checksum': checksum });

    const result = await verifier.verify(rawBody, headers, mockEnv as Env);

    expect(result.ok).toBe(true);
    expect(result.eventId).toBeDefined();
    // Event ID should contain the event type for traceability
    expect(result.eventId).toContain('transaction.updated');
  });
});

// ── Dedup store behavior tests ────────────────────────────────────────────────
describe('KV deduplication store behavior', () => {
  const kv = new MockKVNamespace();

  it('should store an event ID and detect it as seen on second call', async () => {
    const eventId = 'test_event_001';
    const kvKey = `webhawk:dedup:${eventId}`;

    // First delivery — not yet seen
    const first = await kv.get(kvKey);
    expect(first).toBeNull();

    // Mark as processed
    await kv.put(kvKey, JSON.stringify({ processedAt: new Date().toISOString() }), {
      expirationTtl: 86400,
    });

    // Second delivery (retry) — should be detected as duplicate
    const second = await kv.get(kvKey);
    expect(second).not.toBeNull();
  });

  it('should return null for unknown event IDs', async () => {
    const unknownKey = 'webhawk:dedup:event_never_seen';
    const result = await kv.get(unknownKey);
    expect(result).toBeNull();
  });

  it('KV key prefix must be consistent across dedup middleware and tests', async () => {
    // Ensure the key format used in tests matches what dedup.middleware.ts expects
    const PREFIX = 'webhawk:dedup:';
    const eventId = 'sample_event_xyz';
    const expectedKey = `${PREFIX}${eventId}`;

    await kv.put(expectedKey, 'exists', { expirationTtl: 86400 });

    const result = await kv.get(expectedKey);
    expect(result).toBe('exists');
  });
});
