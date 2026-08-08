/**
 * @file ssrf.spec.ts
 * @description ATTACK SIMULATION: SSRF (Server-Side Request Forgery) Attack
 *
 * Threat: An attacker configures a malicious forwarding URL pointing to
 * internal infrastructure (localhost, AWS metadata, private subnets).
 * If WebHawk forwards verified webhooks to this URL, the attacker can
 * probe internal services using our edge worker as a relay.
 *
 * These tests verify that SsrfGuard blocks all dangerous URL patterns.
 */

import { describe, it, expect } from 'vitest';
import { SsrfGuard } from '../../src/core/forward/ssrf.guard.js';

const guard = new SsrfGuard();

describe('ATTACK: SSRF via private IP ranges', () => {
  it('should block localhost', () => {
    const result = guard.validate('https://localhost/api/internal');
    expect(result.safe).toBe(false);
  });

  it('should block 127.0.0.1', () => {
    const result = guard.validate('https://127.0.0.1/data');
    expect(result.safe).toBe(false);
  });

  it('should block 10.x.x.x (RFC 1918 Class A)', () => {
    const result = guard.validate('https://10.0.0.1/internal');
    expect(result.safe).toBe(false);
  });

  it('should block 192.168.x.x (RFC 1918 Class C)', () => {
    const result = guard.validate('https://192.168.1.100/admin');
    expect(result.safe).toBe(false);
  });

  it('should block 172.16-31.x.x (RFC 1918 Class B)', () => {
    expect(guard.validate('https://172.16.0.1/private').safe).toBe(false);
    expect(guard.validate('https://172.31.255.255/private').safe).toBe(false);
  });

  it('should block AWS metadata endpoint (169.254.169.254)', () => {
    const result = guard.validate('https://169.254.169.254/latest/meta-data/');
    expect(result.safe).toBe(false);
  });

  it('should block IPv6 loopback ::1', () => {
    const result = guard.validate('https://[::1]/internal');
    expect(result.safe).toBe(false);
  });

  it('should block 0.0.0.0', () => {
    const result = guard.validate('https://0.0.0.0/');
    expect(result.safe).toBe(false);
  });
});

describe('ATTACK: SSRF via HTTP (non-HTTPS)', () => {
  it('should block plain HTTP destinations', () => {
    const result = guard.validate('http://api.example.com/webhook');
    expect(result.safe).toBe(false);
    expect(result.reason).toContain('HTTPS');
  });

  it('should block FTP scheme', () => {
    const result = guard.validate('ftp://files.example.com/data');
    expect(result.safe).toBe(false);
  });

  it('should block file:// scheme', () => {
    const result = guard.validate('file:///etc/passwd');
    expect(result.safe).toBe(false);
  });
});

describe('ATTACK: SSRF via internal service ports', () => {
  it('should block port 3306 (MySQL)', () => {
    const result = guard.validate('https://public-host.com:3306/data');
    expect(result.safe).toBe(false);
  });

  it('should block port 6379 (Redis)', () => {
    const result = guard.validate('https://public-host.com:6379/');
    expect(result.safe).toBe(false);
  });

  it('should block port 5432 (Postgres)', () => {
    const result = guard.validate('https://public-host.com:5432/');
    expect(result.safe).toBe(false);
  });

  it('should block port 22 (SSH)', () => {
    const result = guard.validate('https://public-host.com:22/');
    expect(result.safe).toBe(false);
  });
});

describe('SSRF Guard — safe URLs', () => {
  it('should allow a legitimate HTTPS URL', () => {
    const result = guard.validate('https://api.example.com/webhook/receive');
    expect(result.safe).toBe(true);
  });

  it('should allow HTTPS with port 443', () => {
    const result = guard.validate('https://hooks.example.com:443/inbound');
    expect(result.safe).toBe(true);
  });

  it('should allow HTTPS with a subdomain', () => {
    const result = guard.validate('https://payments.myapp.io/webhook');
    expect(result.safe).toBe(true);
  });

  it('should reject invalid URLs gracefully', () => {
    const result = guard.validate('not-a-url-at-all');
    expect(result.safe).toBe(false);
    expect(result.reason).toContain('Invalid URL');
  });
});
