/**
 * @file github.verifier.ts
 * @description WebhookVerifier implementation for GitHub webhooks.
 *
 * GitHub Webhook Signature Scheme:
 * - Header: `X-Hub-Signature-256` (format: `sha256=HMAC_HEX`)
 * - Signed payload: raw request body (as bytes)
 * - Algorithm: HMAC-SHA256 with the webhook secret configured in GitHub settings
 *
 * Reference: https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
 *
 * Additional headers for deduplication:
 * - `X-GitHub-Delivery`: unique GUID per delivery (GitHub's event ID)
 * - `X-GitHub-Event`: event type (push, pull_request, etc.)
 *
 * Security invariants:
 * - HMAC computed over rawBody (bytes) directly.
 * - Comparison uses timingSafeCompare.
 * - Secret rotation via GITHUB_WEBHOOK_SECRET_PREV.
 */

import { hmacSha256, timingSafeCompare } from '../core/crypto.utils.js';
import type { Env } from '../core/env.types.js';
import type {
  VerificationResult,
  WebhookVerifier,
} from '../core/verifier.interface.js';

export class GitHubVerifier implements WebhookVerifier<Env> {
  readonly provider = 'github';

  async verify(
    rawBody: ArrayBuffer,
    headers: Headers,
    env: Env,
  ): Promise<VerificationResult> {
    const base: Pick<VerificationResult, 'provider'> = { provider: this.provider };

    const hubSignature = headers.get('x-hub-signature-256');
    const deliveryId = headers.get('x-github-delivery');
    const eventType = headers.get('x-github-event');

    if (!hubSignature) {
      return {
        ...base,
        ok: false,
        reason: 'MISSING_SIGNATURE',
        debugMessage: 'Missing X-Hub-Signature-256 header',
      };
    }

    // ── Strip "sha256=" prefix ────────────────────────────────────────────────
    const providedHex = hubSignature.startsWith('sha256=')
      ? hubSignature.slice(7)
      : hubSignature;

    // ── Try all rotation secrets ───────────────────────────────────────────────
    const secrets: string[] = [env.GITHUB_WEBHOOK_SECRET];
    if (env.GITHUB_WEBHOOK_SECRET_PREV) {
      secrets.push(env.GITHUB_WEBHOOK_SECRET_PREV);
    }

    for (const secret of secrets) {
      // CRITICAL: rawBody is ArrayBuffer — HMAC computed directly over raw bytes.
      const computed = await hmacSha256(secret, rawBody);

      if (timingSafeCompare(computed, providedHex.toLowerCase())) {
        // Use GitHub's delivery ID as the dedup event ID (universally unique per delivery)
        const eventId = deliveryId
          ? `github_${deliveryId}`
          : `github_${eventType ?? 'unknown'}_${Date.now()}`;

        return {
          ...base,
          ok: true,
          eventId,
          // GitHub doesn't embed a timestamp in the signature header
          // Timestamp validation uses request arrival time (handled upstream)
          debugMessage: `X-Hub-Signature-256 verified (event: ${eventType ?? 'unknown'})`,
        };
      }
    }

    return {
      ...base,
      ok: false,
      reason: 'INVALID_SIGNATURE',
      debugMessage: 'X-Hub-Signature-256 did not match computed HMAC-SHA256',
    };
  }
}
