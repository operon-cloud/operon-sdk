import type { OperonConfig } from '../config.js';
import { TransportError } from '../errors.js';

export interface JsonRequestOptions {
  method: string;
  path: string;
  token?: string;
  body?: unknown;
  signal?: AbortSignal;
}

interface AbortSignalConstructor {
  prototype: AbortSignal;
}

/**
 * Issues an HTTP request to the Operon platform, handling JSON serialisation and timeouts.
 *
 * @param config Resolved SDK configuration.
 * @param options Request metadata including method, path, payload, and abort signal.
 */
export async function jsonRequest(
  config: OperonConfig,
  options: JsonRequestOptions
): Promise<Response> {
  const path = options.path.startsWith('/') ? options.path : `/${options.path}`;
  const url = `${config.baseUrl}${path}`;
  const headers = new Headers({
    Accept: 'application/json'
  });

  let payload: BodyInit | null = null;
  if (options.body !== undefined && options.body !== null) {
    const serialized = JSON.stringify(options.body);
    payload = serialized;
    headers.set('Content-Type', 'application/json');
  }

  if (options.token) {
    headers.set('Authorization', `Bearer ${options.token}`);
  }

  const controller = new AbortController();
  const signal = mergeAbortSignals(controller.signal, options.signal);
  const timeout = setTimeout(() => controller.abort(), config.httpTimeoutMs);

  try {
    const response = await config.fetchImpl(url, {
      method: options.method,
      headers,
      body: payload,
      signal
    });
    return response;
  } catch (error) {
    throw new TransportError(`request ${options.method} ${url} failed`, error);
  } finally {
    clearTimeout(timeout);
  }
}

function mergeAbortSignals(base: AbortSignal, override?: AbortSignal): AbortSignal {
  if (!override) {
    return base;
  }

  if (override.aborted) {
    return override;
  }

  if (typeof AbortSignal !== 'undefined') {
    const candidate = AbortSignal as unknown as AbortSignalConstructor & {
      any?: (signals: AbortSignal[]) => AbortSignal;
    };
    if (typeof candidate.any === 'function') {
      return candidate.any([base, override]);
    }
  }

  const controller = new AbortController();
  const abort = () => controller.abort();
  base.addEventListener('abort', abort, { once: true });
  override.addEventListener('abort', abort, { once: true });
  return controller.signal;
}
