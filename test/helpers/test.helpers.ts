/**
 * @file test.helpers.ts
 * @description Test utilities for generating signed webhook requests.
 *
 * These helpers let attack simulation tests create valid, tampered, expired,
 * and replayed webhook requests without relying on real provider infrastructure.
 */

/**
 * Computes HMAC-SHA256 of message using the Web Crypto API.
 * Mirrors the production crypto.utils.ts implementation for test use.
 */
export async function computeHmac(secret: string, message: string | ArrayBuffer): Promise<string> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const messageData = typeof message === 'string' ? encoder.encode(message) : message;

  const key = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );

  const sig = await crypto.subtle.sign('HMAC', key, messageData);
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Computes SHA-256 of a string.
 */
export async function computeSha256(message: string): Promise<string> {
  const data = new TextEncoder().encode(message);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Build a Wompi structured event body for checksum verification tests */
export function buildWompiChecksumBody(params: {
  transactionId: string;
  transactionStatus: string;
  timestamp: number;
}): object {
  return {
    event: 'transaction.updated',
    data: {
      transaction: {
        id: params.transactionId,
        status: params.transactionStatus,
        reference: 'test-order-123',
        amount_in_cents: 5000000,
        currency: 'COP',
      },
    },
    environment: 'test',
    signature: {
      properties: ['transaction.id', 'transaction.status'],
      timestamp: params.timestamp,
      checksum: '', // will be filled by the test
    },
    timestamp: params.timestamp,
    sent_at: new Date(params.timestamp * 1000).toISOString(),
  };
}

/** Compute Wompi's checksum from properties + timestamp + secret */
export async function computeWompiChecksum(params: {
  transactionId: string;
  transactionStatus: string;
  timestamp: number;
  secret: string;
}): Promise<string> {
  const concatenated = `${params.transactionId}${params.transactionStatus}`;
  return computeSha256(`${concatenated}${params.timestamp}${params.secret}`);
}
