/**
 * @file stripe.verifier.ts
 * @description WebhookVerifier implementation for Stripe.
 *
 * Stripe Webhook Signature Scheme:
 * - Header: `Stripe-Signature` (format: `t=TIMESTAMP,v1=HMAC_HEX`)
 * - Signed payload: `${timestamp}.${rawBody}`
 * - Algorithm: HMAC-SHA256 with the webhook signing secret (whsec_...)
 * - Tolerance: 300 seconds (5 minutes) — same as WebHawk's REPLAY_WINDOW_MS
 *
 * Reference: https://stripe.com/docs/webhooks/signatures
 *
 * Security invariants:
 * - HMAC is computed over rawBody (ArrayBuffer), NOT re-parsed JSON.
 * - Comparison uses timingSafeCompare.
 * - Secret rotation supported via STRIPE_WEBHOOK_SECRET_PREV.
 */

import { hmacSha256, timingSafeCompare } from '../core/crypto.utils.js';
import type { Env } from '../core/env.types.js';
import type {
  VerificationResult,
  WebhookVerifier,
} from '../core/verifier.interface.js';

export class StripeVerifier implements WebhookVerifier<Env> {
  readonly provider = 'stripe';

  async verify(
    rawBody: ArrayBuffer,
    headers: Headers,
    env: Env,
  ): Promise<VerificationResult> {
    const base: Pick<VerificationResult, 'provider'> = { provider: this.provider };

    const stripeSignature = headers.get('stripe-signature');

    if (!stripeSignature) {
      return {
        ...base,
        ok: false,
        reason: 'MISSING_SIGNATURE',
        debugMessage: 'Missing Stripe-Signature header',
      };
    }

    // ── Parse Stripe-Signature header ─────────────────────────────────────────
    // Format: "t=1492774577,v1=5257a869e7ecebeda32affa62cdca3fa51cad7e77a05bd445be62f95cfbc4189"
    const parts = Object.fromEntries(
      stripeSignature.split(',').map((part) => {
        const [key, ...values] = part.split('=');
        return [key, values.join('=')];
      }),
    );

    const timestamp = parts['t'];
    const v1Signature = parts['v1'];

    if (!timestamp || !v1Signature) {
      return {
        ...base,
        ok: false,
        reason: 'MALFORMED_PAYLOAD',
        debugMessage: 'Stripe-Signature header missing t= or v1= components',
      };
    }

    const timestampMs = parseInt(timestamp, 10) * 1000;

    if (isNaN(timestampMs)) {
      return {
        ...base,
        ok: false,
        reason: 'MISSING_TIMESTAMP',
        debugMessage: 'Invalid timestamp in Stripe-Signature header',
      };
    }

    // ── Build signed payload: "${timestamp}.${rawBodyText}" ──────────────────
    // CRITICAL: We convert rawBody to text ONLY for concatenation in the signed string.
    // The rawBody ArrayBuffer itself (as bytes) is what was transmitted. Stripe's
    // scheme concatenates timestamp + "." + raw body string. This is equivalent
    // to HMAC over those bytes — not over re-serialized JSON.
    const rawBodyText = new TextDecoder().decode(rawBody);
    const signedPayload = `${timestamp}.${rawBodyText}`;

    // ── Try current and previous secrets (rotation overlap) ───────────────────
    const secrets: string[] = [env.STRIPE_WEBHOOK_SECRET];
    if (env.STRIPE_WEBHOOK_SECRET_PREV) {
      secrets.push(env.STRIPE_WEBHOOK_SECRET_PREV);
    }

    for (const secret of secrets) {
      const computed = await hmacSha256(secret, signedPayload);

      if (timingSafeCompare(computed, v1Signature.toLowerCase())) {
        return {
          ...base,
          ok: true,
          eventId: `stripe_${timestamp}_${v1Signature.substring(0, 16)}`,
          timestampMs,
          debugMessage: 'Stripe-Signature v1 verified',
        };
      }
    }

    return {
      ...base,
      ok: false,
      reason: 'INVALID_SIGNATURE',
      debugMessage: 'Stripe-Signature v1 did not match computed HMAC-SHA256',
    };
  }
}
