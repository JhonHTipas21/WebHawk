/**
 * @file env-validator.spec.ts
 * @description Unit tests for EnvValidator startup checks.
 */

import { describe, it, expect } from 'vitest';
import { EnvValidator } from '../../src/core/config/env-validator.js';
import type { Env } from '../../src/core/env.types.js';

describe('EnvValidator configuration checks', () => {
  const mockKV = {} as KVNamespace;

  it('should pass on a fully valid environment', () => {
    const env: Partial<Env> = {
      WOMPI_SECRET: 'wompi_sec_123',
      STRIPE_WEBHOOK_SECRET: 'whsec_stripe_sec_456',
      GITHUB_WEBHOOK_SECRET: 'github_sec_789',
      DEDUP_KV: mockKV,
    };

    const failures = EnvValidator.validate(env);
    expect(failures).toHaveLength(0);
    expect(() => EnvValidator.assert(env)).not.toThrow();
  });

  it('should flag missing Wompi secret', () => {
    const env: Partial<Env> = {
      STRIPE_WEBHOOK_SECRET: 'whsec_stripe_sec_456',
      GITHUB_WEBHOOK_SECRET: 'github_sec_789',
      DEDUP_KV: mockKV,
    };

    const failures = EnvValidator.validate(env);
    expect(failures).toHaveLength(1);
    expect(failures[0].binding).toBe('WOMPI_SECRET');
    expect(failures[0].error).toContain('Wompi');
  });

  it('should flag empty Wompi secret', () => {
    const env: Partial<Env> = {
      WOMPI_SECRET: '   ',
      STRIPE_WEBHOOK_SECRET: 'whsec_stripe_sec_456',
      GITHUB_WEBHOOK_SECRET: 'github_sec_789',
      DEDUP_KV: mockKV,
    };

    const failures = EnvValidator.validate(env);
    expect(failures).toHaveLength(1);
    expect(failures[0].binding).toBe('WOMPI_SECRET');
  });

  it('should flag missing Stripe secret prefix', () => {
    const env: Partial<Env> = {
      WOMPI_SECRET: 'wompi_sec_123',
      STRIPE_WEBHOOK_SECRET: 'stripe_sec_456_no_prefix',
      GITHUB_WEBHOOK_SECRET: 'github_sec_789',
      DEDUP_KV: mockKV,
    };

    const failures = EnvValidator.validate(env);
    expect(failures).toHaveLength(1);
    expect(failures[0].binding).toBe('STRIPE_WEBHOOK_SECRET');
    expect(failures[0].error).toContain('whsec_');
  });

  it('should flag missing GITHUB secret', () => {
    const env: Partial<Env> = {
      WOMPI_SECRET: 'wompi_sec_123',
      STRIPE_WEBHOOK_SECRET: 'whsec_stripe_sec_456',
      DEDUP_KV: mockKV,
    };

    const failures = EnvValidator.validate(env);
    expect(failures).toHaveLength(1);
    expect(failures[0].binding).toBe('GITHUB_WEBHOOK_SECRET');
  });

  it('should flag missing KV namespace', () => {
    const env: Partial<Env> = {
      WOMPI_SECRET: 'wompi_sec_123',
      STRIPE_WEBHOOK_SECRET: 'whsec_stripe_sec_456',
      GITHUB_WEBHOOK_SECRET: 'github_sec_789',
    };

    const failures = EnvValidator.validate(env);
    expect(failures).toHaveLength(1);
    expect(failures[0].binding).toBe('DEDUP_KV');
  });

  it('should throw an error on assert failure', () => {
    const env: Partial<Env> = {};
    expect(() => EnvValidator.assert(env)).toThrow('validation failed');
  });
});
