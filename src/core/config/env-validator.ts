/**
 * @file env-validator.ts
 * @description Validates the Cloudflare Workers environment bindings on startup.
 *
 * Ensures that all required integration secrets and configurations are present
 * and follow expected structural constraints (e.g., prefix formats).
 *
 * Preventative security: avoids running the proxy in a half-configured state,
 * which could lead to silent authentication bypasses or runtime exceptions.
 */

import type { Env } from '../env.types.js';

export interface ValidationFailure {
  binding: keyof Env | string;
  error: string;
}

export class EnvValidator {
  /**
   * Validates the provided environment bindings.
   *
   * @param env - The Cloudflare environment bindings object.
   * @returns Array of failures. If empty, the environment is valid.
   */
  static validate(env: Partial<Env>): ValidationFailure[] {
    const failures: ValidationFailure[] = [];

    // ── 1. Wompi Secrets ───────────────────────────────────────────────────────
    if (!env.WOMPI_SECRET) {
      failures.push({
        binding: 'WOMPI_SECRET',
        error: 'Missing required Wompi webhook secret',
      });
    } else if (env.WOMPI_SECRET.trim() === '') {
      failures.push({
        binding: 'WOMPI_SECRET',
        error: 'Wompi webhook secret cannot be empty',
      });
    }

    // ── 2. Stripe Secrets ──────────────────────────────────────────────────────
    if (!env.STRIPE_WEBHOOK_SECRET) {
      failures.push({
        binding: 'STRIPE_WEBHOOK_SECRET',
        error: 'Missing required Stripe webhook signing secret',
      });
    } else {
      const secret = env.STRIPE_WEBHOOK_SECRET.trim();
      if (secret === '') {
        failures.push({
          binding: 'STRIPE_WEBHOOK_SECRET',
          error: 'Stripe webhook signing secret cannot be empty',
        });
      } else if (!secret.startsWith('whsec_')) {
        failures.push({
          binding: 'STRIPE_WEBHOOK_SECRET',
          error: 'Stripe signing secret must start with prefix "whsec_"',
        });
      }
    }

    // ── 3. GitHub Secrets ──────────────────────────────────────────────────────
    if (!env.GITHUB_WEBHOOK_SECRET) {
      failures.push({
        binding: 'GITHUB_WEBHOOK_SECRET',
        error: 'Missing required GitHub webhook secret',
      });
    } else if (env.GITHUB_WEBHOOK_SECRET.trim() === '') {
      failures.push({
        binding: 'GITHUB_WEBHOOK_SECRET',
        error: 'GitHub webhook secret cannot be empty',
      });
    }

    // ── 4. KV Namespace Bindings ──────────────────────────────────────────────
    if (!env.DEDUP_KV) {
      failures.push({
        binding: 'DEDUP_KV',
        error: 'Missing required DEDUP_KV namespace binding',
      });
    }

    return failures;
  }

  /**
   * Helper that asserts the environment is valid, throwing a ConfigurationError if not.
   */
  static assert(env: Partial<Env>): void {
    const failures = this.validate(env);
    if (failures.length > 0) {
      const messages = failures.map((f) => `[${f.binding}]: ${f.error}`).join(', ');
      throw new Error(`WebHawk configuration validation failed: ${messages}`);
    }
  }
}
