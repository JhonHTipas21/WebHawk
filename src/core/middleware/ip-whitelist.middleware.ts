/**
 * @file ip-whitelist.middleware.ts
 * @description IP Whitelist middleware for WebHawk.
 *
 * Enforces IP validation before reading the payload or performing crypto operations.
 * If the provider has `allowedIps` configured in the registry, the incoming
 * `cf-connecting-ip` is checked against those CIDR blocks.
 */

import type { Context, Next } from 'hono';
import type { Env, Variables } from '../env.types.js';
import type { VerifierRegistry } from '../verifier.interface.js';
import { IpValidator } from '../security/ip-validator.js';
import { IpWhitelistError, UnsupportedProviderError } from '../errors/errors.js';

export function ipWhitelistMiddleware(registry: VerifierRegistry<Env>) {
  return async (c: Context<{ Bindings: Env; Variables: Variables }>, next: Next): Promise<void> => {
    const providerId = c.req.param('provider');
    const verifier = registry.get(providerId);

    if (!verifier) {
      throw new UnsupportedProviderError(`Provider '${providerId}' is not supported`);
    }

    if (verifier.allowedIps && verifier.allowedIps.length > 0) {
      const clientIp = c.req.header('cf-connecting-ip');

      if (!clientIp) {
        console.warn(`[ip-whitelist] Missing cf-connecting-ip for provider ${providerId}`);
        throw new IpWhitelistError('IP not allowed (missing header)');
      }

      const isAllowed = IpValidator.isIpInCidrRanges(clientIp, verifier.allowedIps);
      if (!isAllowed) {
        console.warn(`[ip-whitelist] Blocked IP ${clientIp} for provider ${providerId}`);
        throw new IpWhitelistError('IP not allowed');
      }
    }

    await next();
  };
}
