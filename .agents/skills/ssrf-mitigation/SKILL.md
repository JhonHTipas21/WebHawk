---
name: ssrf-mitigation
description: Guidelines and best practices for mitigating Server-Side Request Forgery (SSRF) when forwarding incoming requests to custom destinations.
---

# SSRF Mitigation and Forwarding Security Guide

This skill details how to securely validate destination URLs before forwarding webhooks, protecting internal infrastructure from Server-Side Request Forgery (SSRF).

## SSRF Vectors and Threats

When an application allows forwarding webhooks to user-configured or dynamic URLs (e.g., via the `x-webhawk-forward-to` header), attackers can exploit this forwarding mechanism to:
-   Scan internal networks, ports, and services.
-   Access cloud metadata endpoints (e.g., AWS IMDS `169.254.169.254`).
-   Exfiltrate database or microservice credentials by probing loopback interfaces (`127.0.0.1`, `[::1]`).

## Security Guard Rules

Before executing a forward request, apply the following validations on the destination URL:

### 1. Protocol / Scheme Whitelisting
Only allow secure HTTPS schemes. Disallow plain HTTP, FTP, file, gopher, and other unsafe protocols.

```typescript
if (url.protocol !== 'https:') {
  return { safe: false, reason: 'Only HTTPS protocol is allowed' };
}
```

### 2. IP Address Validation (CIDR Restrictions)
Resolve the target hostname and reject any IP that falls within private, loopback, link-local, or multicast CIDR ranges:
-   **Loopback:** `127.0.0.0/8`, `::1/128`
-   **Private IPv4 (RFC 1918):** `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
-   **Link-Local:** `169.254.0.0/16`, `fe80::/10`
-   **Broadcast/Unspecified:** `0.0.0.0`, `::/128`

```typescript
import ipaddr from 'ipaddr.js';

export function isPrivateIp(ipString: string): boolean {
  try {
    const addr = ipaddr.parse(ipString);
    const range = addr.range();
    return range !== 'unicast'; // Loopback, private, link-local are categorized as non-unicast
  } catch {
    return true; // Reject unparseable IPs as unsafe
  }
}
```

### 3. Port Whitelisting
Restrict connections to standard secure web ports. Block connection attempts to database ports (e.g., `3306`, `5432`, `6379`) or administrative services (e.g., `22`, `8080`).

```typescript
const port = url.port ? parseInt(url.port, 10) : 443;
if (port !== 443) {
  return { safe: false, reason: 'Only port 443 is permitted' };
}
```
