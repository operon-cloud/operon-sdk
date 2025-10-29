/**
 * Base error type for all Operon SDK failures.
 */
export class OperonSdkError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'OperonSdkError';
  }
}

/**
 * Raised when client-side validation fails prior to issuing a request.
 */
export class ValidationError extends OperonSdkError {
  constructor(message: string) {
    super(message);
    this.name = 'ValidationError';
  }
}

/**
 * Wraps network/transport level failures when contacting Operon services.
 */
export class TransportError extends OperonSdkError {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = 'TransportError';
    if (cause instanceof Error && cause.stack) {
      this.stack = cause.stack;
    }
  }
}

/**
 * Represents an error response returned by Operon APIs.
 */
export class ApiError extends OperonSdkError {
  constructor(
    message: string,
    public readonly status: number,
    public readonly code?: string,
    public readonly details?: unknown
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

interface ApiErrorPayload {
  code?: string;
  message?: string;
  details?: unknown;
}

/**
 * Attempts to decode a failed HTTP response into an {@link ApiError} instance.
 *
 * @param response HTTP response returned by the Operon API.
 */
export async function decodeApiError(response: Response): Promise<ApiError> {
  let bodyText: string | undefined;
  let payload: ApiErrorPayload | undefined;

  try {
    bodyText = await response.text();
    if (bodyText) {
      payload = JSON.parse(bodyText) as ApiErrorPayload;
    }
  } catch {
    // ignore JSON parse errors and fall back to raw body / status text.
  }

  const message =
    payload?.message?.trim() ||
    bodyText?.trim() ||
    `${response.status} ${response.statusText || 'Unknown Error'}`;

  return new ApiError(message, response.status, payload?.code, payload?.details);
}
