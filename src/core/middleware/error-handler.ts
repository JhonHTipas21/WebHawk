/**
 * @file error-handler.ts
 * @description Global Hono error handling middleware.
 *
 * Catches all thrown exceptions in the routing pipeline, mapping WebHawkError
 * subclasses to their configured HTTP status codes and error payloads.
 *
 * Security: prevents internal stack traces from leaking to public responses
 * by standardizing generic 500 responses for unhandled runtime errors.
 */

import type { Context } from 'hono';
import { WebHawkError } from '../errors/errors.js';

export function errorHandler(err: Error, c: Context): Response {
  // Structured logging of all pipeline errors
  console.error(
    JSON.stringify({
      level: 'ERROR',
      event: 'PIPELINE_ERROR',
      errorName: err.name,
      message: err.message.substring(0, 200),
      stack: err.stack?.substring(0, 500),
    }),
  );

  // Map known domain errors to HTTP responses
  if (err instanceof WebHawkError) {
    return c.json(err.toJSON(), err.statusCode as any);
  }

  // Fallback for unhandled unexpected runtime errors (prevents stack leakage)
  return c.json(
    {
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    },
    500,
  );
}
