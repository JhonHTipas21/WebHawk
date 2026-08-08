/**
 * @file crypto.utils.ts
 * @description Low-level cryptographic utilities for WebHawk.
 *
 * WHY THIS FILE EXISTS (Threat Model Reference):
 * - OWASP and Stripe/Wompi/GitHub security guides mandate that webhook signatures
 *   are verified using HMAC-SHA256 over the RAW REQUEST BODY (bytes), never
 *   over a re-serialized JSON object. Key order changes upon re-parse can
 *   silently invalidate the hash.
 * - Signature comparison MUST be constant-time to prevent timing side-channel
 *   attacks. An attacker timing many `===` comparisons can brute-force the
 *   signature byte by byte.
 *
 * Implementation uses the Web Crypto API (crypto.subtle) — available natively
 * in Cloudflare Workers without nodejs_compat flag.
 */

const ENCODER = new TextEncoder();

/**
 * Computes HMAC-SHA256 of `message` using `secret`.
 *
 * @param secret - The HMAC signing key (your integration secret, as a string).
 * @param message - The message to authenticate. Pass the RAW REQUEST BODY as
 *                  an ArrayBuffer. For string-based auth schemes (Wompi checksum),
 *                  pass the pre-concatenated string as a UTF-8 encoded buffer.
 * @returns Lowercase hex-encoded HMAC-SHA256 digest.
 */
export async function hmacSha256(
  secret: string,
  message: ArrayBuffer | string,
): Promise<string> {
  const keyData = ENCODER.encode(secret);
  const messageData =
    typeof message === 'string' ? ENCODER.encode(message) : message;

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false, // not extractable — key material never leaves crypto subsystem
    ['sign'],
  );

  const signature = await crypto.subtle.sign('HMAC', cryptoKey, messageData);
  return bufferToHex(signature);
}

/**
 * Computes SHA-256 of a message (for non-HMAC use cases like dedup hashing).
 *
 * @param message - String or ArrayBuffer to hash.
 * @returns Lowercase hex-encoded SHA-256 digest.
 */
export async function sha256(message: ArrayBuffer | string): Promise<string> {
  const data =
    typeof message === 'string' ? ENCODER.encode(message) : message;
  const digest = await crypto.subtle.digest('SHA-256', data);
  return bufferToHex(digest);
}

/**
 * Compares two hex strings in CONSTANT TIME.
 *
 * WHY NOT `===`?
 * JavaScript's `===` comparison of strings short-circuits on the first
 * differing character. An attacker can measure response times of thousands
 * of requests to determine where the first mismatch occurs, gradually
 * reconstructing the valid signature (timing side-channel attack).
 *
 * HOW THIS WORKS:
 * crypto.subtle.timingSafeEqual takes two ArrayBuffers and compares them
 * in constant time — the operation always takes the same duration regardless
 * of how many bytes match. NOTE: it throws if lengths differ, so we must
 * handle the length-mismatch case carefully without early-returning (which
 * would itself leak timing information about expected length).
 *
 * @param a - First hex string (e.g., incoming X-Event-Checksum header value).
 * @param b - Second hex string (e.g., computed HMAC).
 * @returns true if identical, false otherwise — always in constant time.
 */
export function timingSafeCompare(a: string, b: string): boolean {
  const bufA = ENCODER.encode(a);
  const bufB = ENCODER.encode(b);

  // If lengths differ, the signatures cannot match.
  // We still run a dummy comparison on bufA vs itself to prevent the
  // short-circuit from revealing the expected length via timing.
  if (bufA.byteLength !== bufB.byteLength) {
    // Dummy constant-time comparison — result is always false, but timing
    // is proportional to bufA.length, not immediately returning on mismatch.
    (crypto.subtle as any).timingSafeEqual(bufA, bufA);
    return false;
  }

  return (crypto.subtle as any).timingSafeEqual(bufA, bufB);
}

/**
 * Converts an ArrayBuffer to a lowercase hex string.
 * Used internally to produce hex digests from crypto.subtle outputs.
 */
export function bufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
