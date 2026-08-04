/**
 * @file wompi.verifier.ts
 * @description WebhookVerifier implementation for Wompi (Colombia/El Salvador).
 *
 * Wompi supports two signature schemes depending on the event type:
 *
 * 1. X-Event-Checksum scheme (Structured events — most common):
 *    Checksum = SHA-256(
 *      values_of(signature.properties) + signature.timestamp + WOMPI_SECRET
 *    )
 *    Reference: https://docs.wompi.co/docs/en/webhooks
 *
 * 2. wompi_hash scheme (HMAC-SHA256 over raw body):
 *    Hash = HMAC-SHA256(rawBody, WOMPI_SECRET)
 *    Header: wompi_hash
 *
 * BOTH schemes are implemented. Detection is header-based.
 *
 * Security invariants (non-negotiable):
 * - rawBody is NEVER re-parsed before hashing (protects key order).
 * - Comparison uses timingSafeCompare (constant-time, prevents timing attacks).
 * - Secrets are read from env.WOMPI_SECRET (and env.WOMPI_SECRET_PREV for rotation).
 * - NEVER logs the secret or full payload.
 */

import { hmacSha256, sha256, timingSafeCompare } from '../core/crypto.utils.js';
import type { Env } from '../core/env.types.js';
import type {
  VerificationResult,
  WebhookVerifier,
} from '../core/verifier.interface.js';

/** Shape of a Wompi structured event (partial — only fields needed for verification). */
interface WompiEventBody {
  signature?: {
    properties?: string[];
    checksum?: string;
    timestamp?: number;
  };
  data?: Record<string, Record<string, unknown>>;
  event?: string;
}

export class WompiVerifier implements WebhookVerifier<Env> {
  readonly provider = 'wompi';

  async verify(
    rawBody: ArrayBuffer,
    headers: Headers,
    env: Env,
  ): Promise<VerificationResult> {
    const base: Pick<VerificationResult, 'provider'> = { provider: this.provider };

    // ── Detect scheme ──────────────────────────────────────────────────────────
    const wompiHash = headers.get('wompi_hash');
    const xEventChecksum = headers.get('x-event-checksum');

    if (wompiHash !== null) {
      return this.verifyHmacScheme(rawBody, wompiHash, env, base);
    }

    if (xEventChecksum !== null) {
      return this.verifyChecksumScheme(rawBody, xEventChecksum, env, base);
    }

    // No recognizable Wompi signature header found
    return {
      ...base,
      ok: false,
      reason: 'MISSING_SIGNATURE',
      debugMessage: 'Neither wompi_hash nor x-event-checksum header present',
    };
  }

  // ── Scheme 1: wompi_hash (HMAC-SHA256 over raw body) ─────────────────────────

  /**
   * Verifies the wompi_hash header using HMAC-SHA256 over raw bytes.
   *
   * Critical: rawBody is passed as-is (ArrayBuffer). We never parse it here.
   * Secret rotation: tries current secret first, then previous if rotation is active.
   */
  private async verifyHmacScheme(
    rawBody: ArrayBuffer,
    providedHash: string,
    env: Env,
    base: Pick<VerificationResult, 'provider'>,
  ): Promise<VerificationResult> {
    const secrets = this.resolveSecrets(env.WOMPI_SECRET, env.WOMPI_SECRET_PREV);

    for (const secret of secrets) {
      const computed = await hmacSha256(secret, rawBody);

      if (timingSafeCompare(computed, providedHash.toLowerCase())) {
        // Extract a stable event ID for deduplication from the raw body
        const eventId = await this.extractEventId(rawBody);
        return {
          ...base,
          ok: true,
          eventId,
          // No timestamp extracted from this scheme — caller uses request arrival time
          debugMessage: 'wompi_hash verified via HMAC-SHA256',
        };
      }
    }

    return {
      ...base,
      ok: false,
      reason: 'INVALID_SIGNATURE',
      debugMessage: 'wompi_hash did not match computed HMAC-SHA256 (checked all rotation secrets)',
    };
  }

  // ── Scheme 2: x-event-checksum (SHA-256 of structured fields) ────────────────

  /**
   * Verifies the x-event-checksum header.
   *
   * Checksum = SHA-256(field1_value + field2_value + ... + timestamp + secret)
   *
   * The list of fields is declared in body.signature.properties.
   * We read field values from body.data[fieldPath], concatenate in declared order,
   * append timestamp and secret, then hash.
   *
   * NOTE: We still parse the JSON here, because the checksum algorithm itself
   * is defined as field-level concatenation, NOT over raw bytes.
   * The important thing is that the values we extract from JSON are the canonical
   * source — we never re-serialize and hash that result.
   */
  private async verifyChecksumScheme(
    rawBody: ArrayBuffer,
    providedChecksum: string,
    env: Env,
    base: Pick<VerificationResult, 'provider'>,
  ): Promise<VerificationResult> {
    let body: WompiEventBody;

    try {
      const text = new TextDecoder().decode(rawBody);
      body = JSON.parse(text) as WompiEventBody;
    } catch {
      return {
        ...base,
        ok: false,
        reason: 'MALFORMED_PAYLOAD',
        debugMessage: 'Failed to JSON-parse request body for checksum verification',
      };
    }

    const { signature, data } = body;

    if (!signature?.properties || !Array.isArray(signature.properties)) {
      return {
        ...base,
        ok: false,
        reason: 'MALFORMED_PAYLOAD',
        debugMessage: 'Missing signature.properties in Wompi event body',
      };
    }

    if (typeof signature.timestamp !== 'number') {
      return {
        ...base,
        ok: false,
        reason: 'MISSING_TIMESTAMP',
        debugMessage: 'Missing or invalid signature.timestamp in Wompi event body',
      };
    }

    // Build the concatenation string from declared properties
    const concatenated = signature.properties
      .map((prop) => {
        // prop is dotted path like "transaction.id" or "transaction.status"
        const [entity, field] = prop.split('.');
        if (!entity || !field) return '';
        const entityData = data?.[entity];
        if (!entityData) return '';
        const value = entityData[field];
        return value !== undefined && value !== null ? String(value) : '';
      })
      .join('');

    const secrets = this.resolveSecrets(env.WOMPI_SECRET, env.WOMPI_SECRET_PREV);

    for (const secret of secrets) {
      const preimage = `${concatenated}${signature.timestamp}${secret}`;
      const computed = await sha256(preimage);

      if (timingSafeCompare(computed, providedChecksum.toLowerCase())) {
        // Extract event ID for deduplication
        const eventId = body.event
          ? `${body.event}_${signature.timestamp}`
          : await this.extractEventId(rawBody);

        return {
          ...base,
          ok: true,
          eventId,
          timestampMs: signature.timestamp * 1000,
          debugMessage: 'x-event-checksum verified via SHA-256 field concatenation',
        };
      }
    }

    return {
      ...base,
      ok: false,
      reason: 'INVALID_SIGNATURE',
      debugMessage: 'x-event-checksum did not match computed SHA-256 (checked all rotation secrets)',
    };
  }

  // ── Helpers ───────────────────────────────────────────────────────────────────

  /**
   * Resolves the list of active secrets, including the previous one if in rotation.
   * Order: current first (most likely to match), previous second.
   *
   * Why overlap window?
   * If you replace WOMPI_SECRET immediately, any webhook "in flight" signed with
   * the old key will be rejected until it expires on Wompi's side. The overlap
   * window gives time for in-transit webhooks to drain.
   */
  private resolveSecrets(current: string, previous?: string): string[] {
    const secrets = [current];
    if (previous && previous !== current) {
      secrets.push(previous);
    }
    return secrets;
  }

  /**
   * Produces a stable, provider-agnostic event ID from the raw body.
   * Used as fallback when the provider doesn't supply a unique event identifier.
   *
   * The ID is a SHA-256 of the raw bytes — deterministic across retries
   * (same payload = same ID), which is exactly what deduplication needs.
   */
  private async extractEventId(rawBody: ArrayBuffer): Promise<string> {
    return `wompi_${await sha256(rawBody)}`;
  }
}
