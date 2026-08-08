/**
 * @file errors.ts
 * @description Centralized custom error classes for the WebHawk application.
 *
 * Provides a clean hierarchy of errors matching specific security failure states.
 * Encapsulates HTTP status codes and internal error codes.
 */

export abstract class WebHawkError extends Error {
  abstract readonly statusCode: number;
  abstract readonly errorCode: string;

  constructor(message: string) {
    super(message);
    this.name = this.constructor.name;
    Object.setPrototypeOf(this, new.target.prototype);
  }

  /**
   * Serializes the error to a JSON response payload format.
   */
  toJSON() {
    return {
      error: this.message,
      code: this.errorCode,
    };
  }
}

export class SignatureVerificationError extends WebHawkError {
  readonly statusCode = 401;
  readonly errorCode = 'INVALID_SIGNATURE';
}

export class RateLimitExceededError extends WebHawkError {
  readonly statusCode = 429;
  readonly errorCode = 'RATE_LIMITED';
}

export class ReplayDetectedError extends WebHawkError {
  readonly statusCode = 401;
  readonly errorCode = 'EXPIRED_TIMESTAMP';
}

export class ConfigurationError extends WebHawkError {
  readonly statusCode = 500;
  readonly errorCode = 'CONFIGURATION_ERROR';
}

export class SSRFBlockedError extends WebHawkError {
  readonly statusCode = 400;
  readonly errorCode = 'SSRF_BLOCKED';
}

export class UnsupportedProviderError extends WebHawkError {
  readonly statusCode = 404;
  readonly errorCode = 'UNSUPPORTED_PROVIDER';
}

export class MalformedPayloadError extends WebHawkError {
  readonly statusCode = 400;
  readonly errorCode = 'MALFORMED_PAYLOAD';
}
