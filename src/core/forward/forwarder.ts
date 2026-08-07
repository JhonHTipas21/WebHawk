/**
 * @file forwarder.ts
 * @description Webhook forwarder — proxies verified requests to their real destination.
 *
 * Only runs AFTER all verifications pass:
 * 1. ✅ HMAC verified
 * 2. ✅ Timestamp within window
 * 3. ✅ Not a duplicate
 * 4. ✅ Rate limit not exceeded
 * 5. ✅ SSRF guard cleared
 *
 * Forwards the original rawBody (ArrayBuffer), not any parsed/re-serialized form.
 * Strips internal Webhawk headers, forwards original provider headers.
 */

import { SsrfGuard } from './ssrf.guard.js';

const ssrfGuard = new SsrfGuard();

export interface ForwardResult {
  success: boolean;
  statusCode?: number;
  error?: string;
}

/**
 * Forwards the verified webhook to the configured destination URL.
 *
 * @param destinationUrl - The user-configured URL to forward to.
 * @param rawBody - The raw request body (same bytes that were HMAC-verified).
 * @param originalHeaders - Headers from the original provider request.
 * @returns ForwardResult with HTTP status from the destination.
 */
export async function forwardWebhook(
  destinationUrl: string,
  rawBody: ArrayBuffer,
  originalHeaders: Headers,
): Promise<ForwardResult> {
  // ── SSRF guard ────────────────────────────────────────────────────────────────
  const ssrfCheck = ssrfGuard.validate(destinationUrl);

  if (!ssrfCheck.safe) {
    return {
      success: false,
      error: `SSRF guard blocked forwarding: ${ssrfCheck.reason}`,
    };
  }

  // ── Build forwarding headers ──────────────────────────────────────────────────
  const forwardHeaders = new Headers();

  // Forward safe content headers from original request
  const allowedForwardHeaders = [
    'content-type',
    'x-event-checksum',
    'wompi_hash',
    'stripe-signature',
    'x-hub-signature-256',
    'x-request-id',
    'x-delivery-id',
  ];

  for (const header of allowedForwardHeaders) {
    const value = originalHeaders.get(header);
    if (value !== null) {
      forwardHeaders.set(header, value);
    }
  }

  // Add WebHawk metadata headers
  forwardHeaders.set('x-webhawk-forwarded', 'true');
  forwardHeaders.set('x-webhawk-verified-at', new Date().toISOString());

  // ── Forward request ───────────────────────────────────────────────────────────
  try {
    const response = await fetch(destinationUrl, {
      method: 'POST',
      headers: forwardHeaders,
      body: rawBody,
    });

    return {
      success: response.ok,
      statusCode: response.status,
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Unknown network error';
    return {
      success: false,
      error: message.substring(0, 200), // Truncate, never log full network errors
    };
  }
}
