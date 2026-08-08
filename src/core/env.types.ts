/**
 * @file env.types.ts
 * @description Cloudflare Workers environment bindings type definition.
 *
 * Centralizes all env bindings so they can be referenced type-safely across
 * middlewares and verifiers. Update this as new KV namespaces or secrets are added.
 */

import type { VerificationResult } from './verifier.interface.js';

export interface Env {
  // ── Secrets (bound as plaintext vars in wrangler.toml / Workers dashboard) ──
  /** Wompi Integration Secret for HMAC/checksum verification */
  WOMPI_SECRET: string;
  /** Previous Wompi secret — used during rotation overlap window */
  WOMPI_SECRET_PREV?: string;

  /** Stripe webhook signing secret (whsec_...) */
  STRIPE_WEBHOOK_SECRET: string;
  /** Previous Stripe secret — rotation overlap */
  STRIPE_WEBHOOK_SECRET_PREV?: string;

  /** GitHub webhook secret */
  GITHUB_WEBHOOK_SECRET: string;
  /** Previous GitHub secret — rotation overlap */
  GITHUB_WEBHOOK_SECRET_PREV?: string;

  /** Egress signing secret for signing outgoing forwarded requests */
  EGRESS_SIGNING_SECRET?: string;
  /** Previous egress signing secret — rotation overlap */
  EGRESS_SIGNING_SECRET_PREV?: string;

  // ── KV Namespaces ──
  /**
   * KV namespace for storing processed event IDs (deduplication).
   * Entries are stored with TTL = 24h (well beyond the 5-min replay window).
   */
  DEDUP_KV: KVNamespace;

  // ── Config vars ──
  /** Deployment environment: "development" | "staging" | "production" */
  ENVIRONMENT: string;
}

export interface Variables {
  rawBody: ArrayBuffer;
  verificationResult: VerificationResult;
  webhookTimestampMs: number;
  dedupEventId: string;
}
