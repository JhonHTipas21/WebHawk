/**
 * @file audit.logger.ts
 * @description Structured audit logger for WebHawk.
 *
 * SECURITY RULES (non-negotiable):
 * 1. NEVER log HMAC secrets or signing keys.
 * 2. NEVER log the full request payload — it may contain PII or card data.
 * 3. Log enough metadata to reconstruct the event timeline for debugging
 *    and incident response, without exposing sensitive data.
 *
 * Logged fields (all safe for production log storage):
 * - provider: who sent the webhook
 * - eventId: for correlation with dedup store
 * - outcome: VERIFIED | REJECTED | DUPLICATE | RATE_LIMITED
 * - reason: failure code if rejected
 * - timestampMs: webhook timestamp (from provider)
 * - requestTimestampMs: when we received it
 * - ip: sender IP (for rate limit auditing)
 * - cfRay: Cloudflare Ray ID (for CF support correlation)
 * - environment: prod/staging/dev
 *
 * NOT logged:
 * - request body (even partial)
 * - any header value that could be a secret (Authorization, wompi_hash, etc.)
 * - HMAC secrets
 */

import type { VerificationResult } from '../verifier.interface.js';

export type AuditOutcome = 'VERIFIED' | 'REJECTED' | 'DUPLICATE' | 'RATE_LIMITED';

export interface AuditEntry {
  level: 'INFO' | 'WARN' | 'ERROR';
  event: string;
  outcome: AuditOutcome;
  provider: string;
  eventId?: string;
  reason?: string;
  webhookTimestampMs?: number;
  requestTimestampMs: number;
  ip: string;
  cfRay?: string;
  environment: string;
  durationMs?: number;
}

export class AuditLogger {
  private readonly environment: string;

  constructor(environment: string) {
    this.environment = environment;
  }

  /**
   * Logs the outcome of a webhook verification attempt.
   * Uses structured JSON output compatible with Cloudflare Workers Logpush
   * and Supabase/Postgres ingestion.
   */
  log(
    entry: Omit<AuditEntry, 'level' | 'event' | 'requestTimestampMs' | 'environment'> & {
      requestTimestampMs?: number;
    },
  ): void {
    const fullEntry: AuditEntry = {
      level: entry.outcome === 'VERIFIED' || entry.outcome === 'DUPLICATE' ? 'INFO' : 'WARN',
      event: 'WEBHAWK_AUDIT',
      requestTimestampMs: entry.requestTimestampMs ?? Date.now(),
      environment: this.environment,
      ...entry,
    };

    // Cloudflare Workers structured logging — outputs to Workers Logs/Logpush
    console.log(JSON.stringify(fullEntry));
  }

  /**
   * Logs a successful verification.
   */
  logVerified(params: {
    result: VerificationResult;
    ip: string;
    cfRay?: string;
    durationMs?: number;
  }): void {
    this.log({
      outcome: 'VERIFIED',
      provider: params.result.provider,
      eventId: params.result.eventId,
      webhookTimestampMs: params.result.timestampMs,
      ip: params.ip,
      cfRay: params.cfRay,
      durationMs: params.durationMs,
    });
  }

  /**
   * Logs a rejected webhook (signature invalid, timestamp expired, etc.).
   */
  logRejected(params: {
    result: VerificationResult;
    ip: string;
    cfRay?: string;
  }): void {
    this.log({
      outcome: 'REJECTED',
      provider: params.result.provider,
      reason: params.result.reason,
      eventId: params.result.eventId,
      ip: params.ip,
      cfRay: params.cfRay,
    });
  }

  /**
   * Logs a silently swallowed duplicate event.
   */
  logDuplicate(params: {
    provider: string;
    eventId: string;
    ip: string;
    cfRay?: string;
  }): void {
    this.log({
      outcome: 'DUPLICATE',
      provider: params.provider,
      eventId: params.eventId,
      ip: params.ip,
      cfRay: params.cfRay,
    });
  }

  /**
   * Logs a rate-limited request.
   */
  logRateLimited(params: { provider: string; ip: string; cfRay?: string }): void {
    this.log({
      outcome: 'RATE_LIMITED',
      provider: params.provider,
      ip: params.ip,
      cfRay: params.cfRay,
      reason: 'RATE_LIMITED',
    });
  }
}
