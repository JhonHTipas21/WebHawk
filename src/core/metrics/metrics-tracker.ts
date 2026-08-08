/**
 * @file metrics-tracker.ts
 * @description Request metrics tracking for WebHawk.
 *
 * Provides per-provider counters for verified, rejected, duplicate, and
 * rate-limited events. Counters are accumulated in memory per request and
 * optionally persisted to Cloudflare KV for aggregation across instances.
 *
 * This class is designed to be instantiated per-request and flushed at the
 * end of the request lifecycle to minimize KV write overhead.
 */

export interface ProviderMetrics {
  provider: string;
  verified: number;
  rejected: number;
  duplicate: number;
  rateLimited: number;
  totalRequests: number;
  totalDurationMs: number;
}

export interface MetricsSnapshot {
  timestamp: string;
  providers: Record<string, ProviderMetrics>;
}

export class MetricsTracker {
  private static readonly KV_KEY_PREFIX = 'webhawk:metrics:';
  private static readonly METRICS_TTL_SECONDS = 3600; // 1 hour rolling window

  /**
   * Increments a specific metric counter for a provider in KV.
   *
   * @param kv - Cloudflare KV namespace.
   * @param provider - The provider name (e.g. 'wompi', 'stripe', 'github').
   * @param field - The metric field to increment.
   * @param durationMs - Optional duration for latency tracking.
   */
  static async increment(
    kv: KVNamespace,
    provider: string,
    field: keyof Omit<ProviderMetrics, 'provider'>,
    durationMs?: number,
  ): Promise<void> {
    const key = `${this.KV_KEY_PREFIX}${provider}`;
    const existing = await kv.get(key, 'json') as ProviderMetrics | null;

    const current: ProviderMetrics = existing ?? {
      provider,
      verified: 0,
      rejected: 0,
      duplicate: 0,
      rateLimited: 0,
      totalRequests: 0,
      totalDurationMs: 0,
    };

    current[field] = (current[field] as number) + 1;
    current.totalRequests = current.totalRequests + 1;

    if (durationMs !== undefined) {
      current.totalDurationMs = current.totalDurationMs + durationMs;
    }

    await kv.put(key, JSON.stringify(current), {
      expirationTtl: this.METRICS_TTL_SECONDS,
    });
  }

  /**
   * Retrieves a snapshot of all provider metrics from KV.
   *
   * @param kv - Cloudflare KV namespace.
   * @param providers - List of provider names to collect metrics for.
   * @returns MetricsSnapshot with per-provider stats.
   */
  static async getSnapshot(kv: KVNamespace, providers: string[]): Promise<MetricsSnapshot> {
    const entries = await Promise.all(
      providers.map(async (provider) => {
        const key = `${this.KV_KEY_PREFIX}${provider}`;
        const metrics = await kv.get(key, 'json') as ProviderMetrics | null;
        return [
          provider,
          metrics ?? {
            provider,
            verified: 0,
            rejected: 0,
            duplicate: 0,
            rateLimited: 0,
            totalRequests: 0,
            totalDurationMs: 0,
          },
        ] as [string, ProviderMetrics];
      }),
    );

    return {
      timestamp: new Date().toISOString(),
      providers: Object.fromEntries(entries),
    };
  }

  /**
   * Computes the average latency in milliseconds for a provider.
   */
  static averageLatencyMs(metrics: ProviderMetrics): number {
    if (metrics.totalRequests === 0) return 0;
    return Math.round(metrics.totalDurationMs / metrics.totalRequests);
  }
}
