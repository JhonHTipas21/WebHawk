/**
 * @file errors.spec.ts
 * @description Unit tests for WebHawkError classes and errorHandler middleware.
 */

import { describe, it, expect } from 'vitest';
import { Hono } from 'hono';
import {
  SignatureVerificationError,
  RateLimitExceededError,
  ReplayDetectedError,
  SSRFBlockedError,
  ConfigurationError,
} from '../../src/core/errors/errors.js';
import { errorHandler } from '../../src/core/middleware/error-handler.js';

describe('WebHawkError custom hierarchy', () => {
  it('should serialize SignatureVerificationError correctly', () => {
    const err = new SignatureVerificationError('Invalid signature provided');
    expect(err.statusCode).toBe(401);
    expect(err.errorCode).toBe('INVALID_SIGNATURE');
    expect(err.toJSON()).toEqual({
      error: 'Invalid signature provided',
      code: 'INVALID_SIGNATURE',
    });
  });

  it('should serialize RateLimitExceededError correctly', () => {
    const err = new RateLimitExceededError('Rate limit exceeded');
    expect(err.statusCode).toBe(429);
    expect(err.errorCode).toBe('RATE_LIMITED');
  });

  it('should serialize ReplayDetectedError correctly', () => {
    const err = new ReplayDetectedError('Replay detected');
    expect(err.statusCode).toBe(401);
    expect(err.errorCode).toBe('EXPIRED_TIMESTAMP');
  });

  it('should serialize SSRFBlockedError correctly', () => {
    const err = new SSRFBlockedError('SSRF blocked');
    expect(err.statusCode).toBe(400);
    expect(err.errorCode).toBe('SSRF_BLOCKED');
  });

  it('should serialize ConfigurationError correctly', () => {
    const err = new ConfigurationError('Configuration error');
    expect(err.statusCode).toBe(500);
    expect(err.errorCode).toBe('CONFIGURATION_ERROR');
  });
});

describe('errorHandler middleware routing test', () => {
  it('should map WebHawkError to proper response and status code', async () => {
    const app = new Hono();
    app.onError(errorHandler);
    app.get('/throw', () => {
      throw new SignatureVerificationError('Bad signature');
    });

    const res = await app.request('/throw');
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body).toEqual({
      error: 'Bad signature',
      code: 'INVALID_SIGNATURE',
    });
  });

  it('should fallback to 500 on unexpected errors', async () => {
    const app = new Hono();
    app.onError(errorHandler);
    app.get('/throw-unhandled', () => {
      throw new Error('Unexpected DB timeout');
    });

    const res = await app.request('/throw-unhandled');
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body).toEqual({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    });
  });
});
