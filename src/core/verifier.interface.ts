/**
 * @file verifier.interface.ts
 * @description Core interfaces for WebhookVerifier abstraction.
 *
 * SOLID — Interface Segregation + Dependency Inversion:
 * - Any provider (Wompi, Stripe, GitHub) implements WebhookVerifier<THeaders>.
 * - The proxy pipeline depends ONLY on this abstraction, never on concrete verifiers.
 * - ForwardService depends on ForwardVerifier (separate interface), never mixed with verification logic.
 */

/** Result returned by any WebhookVerifier.verify() call. */
export interface VerificationResult {
  /** Whether all checks passed. */
  ok: boolean;
  /** Short machine-readable reason for failures (never includes secrets or full PII). */
  reason?: VerificationFailureReason;
  /** Human-readable debug message — safe to log, no secrets. */
  debugMessage?: string;
  /**
   * Extracted event ID for downstream deduplication.
   * May be provider-supplied or a stable hash of rawBody + key headers.
   */
  eventId?: string;
  /** Parsed timestamp from the webhook (ms since epoch), for TTL and replay checks. */
  timestampMs?: number;
  /** Provider-specific name, e.g. "wompi", "stripe", "github". */
  provider: string;
}

export type VerificationFailureReason =
  | 'INVALID_SIGNATURE'
  | 'MISSING_SIGNATURE'
  | 'EXPIRED_TIMESTAMP'
  | 'MISSING_TIMESTAMP'
  | 'MALFORMED_PAYLOAD'
  | 'UNSUPPORTED_PROVIDER';

/**
 * Contract that every provider-specific verifier MUST implement.
 *
 * @typeParam TEnv - The Cloudflare Workers env bindings type.
 *
 * Invariant (non-negotiable, per threat model):
 * 1. verify() MUST operate on rawBody (bytes), NEVER on re-parsed JSON.
 * 2. Signature comparison MUST use crypto.subtle.timingSafeEqual (constant-time).
 * 3. verify() is pure validation — it MUST NOT perform network I/O or KV access.
 */
export interface WebhookVerifier<TEnv = Record<string, string>> {
  /** Provider identifier, e.g. "wompi" | "stripe" | "github". */
  readonly provider: string;

  /**
   * Optional array of allowed CIDR blocks for this provider.
   * If defined, the IP whitelist middleware will reject requests from IPs outside these ranges.
   */
  readonly allowedIps?: string[];

  /**
   * Verifies the authenticity and integrity of an incoming webhook request.
   *
   * @param rawBody - The raw request body as an ArrayBuffer (captured BEFORE any JSON parsing).
   * @param headers - The request headers (read-only).
   * @param env - Cloudflare Worker environment bindings (for secrets via env vars, never hardcoded).
   * @returns A VerificationResult indicating pass/fail and extracted metadata.
   */
  verify(
    rawBody: ArrayBuffer,
    headers: Headers,
    env: TEnv,
  ): Promise<VerificationResult>;
}

/**
 * Registry of verifiers keyed by provider name.
 * Enables O/C principle: add providers without modifying the pipeline.
 */
export type VerifierRegistry<TEnv = Record<string, string>> = Map<
  string,
  WebhookVerifier<TEnv>
>;
