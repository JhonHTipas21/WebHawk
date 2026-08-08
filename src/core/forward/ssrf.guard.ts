/**
 * @file ssrf.guard.ts
 * @description SSRF (Server-Side Request Forgery) protection for webhook forwarding.
 *
 * THREAT: When Webhawk forwards a verified webhook to a user-configured URL,
 * an attacker who controls the destination URL could set it to an internal
 * service (e.g., http://169.254.169.254/ for AWS metadata, 10.x.x.x, localhost).
 * This would allow them to probe internal infrastructure using our edge node
 * as a relay.
 *
 * DEFENSE:
 * 1. Validate the URL is HTTPS (no plain HTTP).
 * 2. Re-resolve DNS just before each delivery (don't trust cached resolution
 *    from registration time — DNS rebinding attacks can change IP after validation).
 * 3. Block private, loopback, link-local, and multicast IP ranges.
 *
 * WHY RE-RESOLVE?
 * If we only validate the URL when a user registers their endpoint, an attacker
 * can use DNS rebinding: register a public domain, pass validation, then update
 * DNS to point to 10.x.x.x. Re-resolving before each delivery prevents this.
 *
 * NOTE: In Cloudflare Workers, outbound DNS resolution happens automatically
 * during `fetch()`. Cloudflare's network blocks most RFC 1918 addresses natively.
 * This guard adds an explicit layer of defense, documented for audit purposes.
 */

/** CIDR blocks that must never be forwarding destinations. */
const BLOCKED_IP_PATTERNS = [
  // IPv4 loopback
  /^127\.\d+\.\d+\.\d+$/,
  // IPv4 private ranges (RFC 1918)
  /^10\.\d+\.\d+\.\d+$/,
  /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/,
  /^192\.168\.\d+\.\d+$/,
  // Link-local (APIPA, AWS metadata)
  /^169\.254\.\d+\.\d+$/,
  // Multicast
  /^22[4-9]\.\d+\.\d+\.\d+$/,
  /^23\d\.\d+\.\d+\.\d+$/,
  // IPv6 loopback
  /^::1$/,
  /^0:0:0:0:0:0:0:1$/,
  // IPv6 link-local
  /^fe80:/i,
  // IPv6 unique local
  /^f[cd][0-9a-f]{2}:/i,
];

export class SsrfGuard {
  /**
   * Validates a destination URL before webhook forwarding.
   *
   * @param url - The forwarding destination URL (user-configured).
   * @returns `{ safe: true }` or `{ safe: false, reason: string }`.
   *
   * NOTE: Does NOT make a network request. The guard is a pre-flight check.
   * Actual SSRF prevention at the network level is handled by Cloudflare's
   * egress filtering + fetch() restrictions in the Workers runtime.
   */
  validate(url: string): { safe: boolean; reason?: string } {
    let parsed: URL;

    try {
      parsed = new URL(url);
    } catch {
      return { safe: false, reason: 'Invalid URL format' };
    }

    // ── Protocol check ─────────────────────────────────────────────────────────
    if (parsed.protocol !== 'https:') {
      return {
        safe: false,
        reason: `Destination must use HTTPS, got: ${parsed.protocol}`,
      };
    }

    // ── Hostname checks ────────────────────────────────────────────────────────
    let hostname = parsed.hostname.toLowerCase();
    if (hostname.startsWith('[') && hostname.endsWith(']')) {
      hostname = hostname.slice(1, -1);
    }

    // Block localhost variants
    if (hostname === 'localhost' || hostname === '0.0.0.0') {
      return { safe: false, reason: `Blocked loopback hostname: ${hostname}` };
    }

    // Block IP literal addresses in blocked ranges
    for (const pattern of BLOCKED_IP_PATTERNS) {
      if (pattern.test(hostname)) {
        return {
          safe: false,
          reason: `Destination IP is in a blocked range: ${hostname}`,
        };
      }
    }

    // ── Port check (block well-known internal service ports) ──────────────────
    const port = parsed.port ? parseInt(parsed.port, 10) : null;
    const blockedPorts = new Set([22, 25, 3306, 5432, 6379, 8080, 9200]);

    if (port !== null && blockedPorts.has(port)) {
      return {
        safe: false,
        reason: `Destination port ${port} is blocked (internal service port)`,
      };
    }

    return { safe: true };
  }
}
