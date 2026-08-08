/**
 * @file metrics.spec.ts
 * @description Unit tests for MetricsTracker counter and snapshot logic.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { MetricsTracker } from '../../src/core/metrics/metrics-tracker.js';
import type { ProviderMetrics } from '../../src/core/metrics/metrics-tracker.js';

// In-memory KV implementation for tests
class MockKV {
  private store = new Map<string, string>();

  async get(key: string, type?: string) {
    const value = this.store.get(key);
    if (!value) return null;
    if (type === 'json') return JSON.parse(value);
    return value;
  }

  async put(key: string, value: string, _opts?: { expirationTtl?: number }) {
    this.store.set(key, value);
  }

  clear() {
    this.store.clear();
  }
}

describe('MetricsTracker', () => {
  let kv: MockKV;

  beforeEach(() => {
    kv = new MockKV();
  });

  it('should initialize empty counters on first increment', async () => {
    await MetricsTracker.increment(kv as unknown as KVNamespace, 'stripe', 'verified', 45);
    const snapshot = await MetricsTracker.getSnapshot(kv as unknown as KVNamespace, ['stripe']);

    const stripe = snapshot.providers['stripe'];
    expect(stripe.verified).toBe(1);
    expect(stripe.rejected).toBe(0);
    expect(stripe.duplicate).toBe(0);
    expect(stripe.totalRequests).toBe(1);
    expect(stripe.totalDurationMs).toBe(45);
  });

  it('should accumulate multiple increments for a provider', async () => {
    await MetricsTracker.increment(kv as unknown as KVNamespace, 'wompi', 'verified', 30);
    await MetricsTracker.increment(kv as unknown as KVNamespace, 'wompi', 'verified', 50);
    await MetricsTracker.increment(kv as unknown as KVNamespace, 'wompi', 'rejected');

    const snapshot = await MetricsTracker.getSnapshot(kv as unknown as KVNamespace, ['wompi']);
    const wompi = snapshot.providers['wompi'];

    expect(wompi.verified).toBe(2);
    expect(wompi.rejected).toBe(1);
    expect(wompi.totalRequests).toBe(3);
    expect(wompi.totalDurationMs).toBe(80);
  });

  it('should return zero-value metrics for providers with no data', async () => {
    const snapshot = await MetricsTracker.getSnapshot(kv as unknown as KVNamespace, ['github']);
    const github = snapshot.providers['github'];

    expect(github.verified).toBe(0);
    expect(github.rejected).toBe(0);
    expect(github.totalRequests).toBe(0);
  });

  it('should compute average latency correctly', () => {
    const metrics: ProviderMetrics = {
      provider: 'stripe',
      verified: 4,
      rejected: 0,
      duplicate: 0,
      rateLimited: 0,
      totalRequests: 4,
      totalDurationMs: 200,
    };

    const avg = MetricsTracker.averageLatencyMs(metrics);
    expect(avg).toBe(50);
  });

  it('should return 0 average latency when no requests exist', () => {
    const metrics: ProviderMetrics = {
      provider: 'stripe',
      verified: 0,
      rejected: 0,
      duplicate: 0,
      rateLimited: 0,
      totalRequests: 0,
      totalDurationMs: 0,
    };

    expect(MetricsTracker.averageLatencyMs(metrics)).toBe(0);
  });

  it('should snapshot multiple providers independently', async () => {
    await MetricsTracker.increment(kv as unknown as KVNamespace, 'stripe', 'verified', 20);
    await MetricsTracker.increment(kv as unknown as KVNamespace, 'github', 'rejected');

    const snapshot = await MetricsTracker.getSnapshot(kv as unknown as KVNamespace, ['stripe', 'github', 'wompi']);

    expect(snapshot.providers['stripe'].verified).toBe(1);
    expect(snapshot.providers['github'].rejected).toBe(1);
    expect(snapshot.providers['wompi'].totalRequests).toBe(0);
    expect(snapshot.timestamp).toBeTruthy();
  });
});
