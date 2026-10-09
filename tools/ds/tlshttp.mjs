/**
 * tools/ds/tlshttp.mjs — `tls --http`: what each endpoint answers to `GET /`. Over the TLS
 * connection the handshake opened (ALPN http/1.1, the host in SNI and in `Host`): the status and
 * the Strict-Transport-Security header (lib/origincompare.js parseHsts, as a browser reads it);
 * for a port-443 target also over plain HTTP to port 80 of the same address: does it redirect to
 * https://? Only the status line and the headers are read; the connection is dropped before the
 * body. `request` is injectable (tests answer from a local server).
 */

import http from 'node:http';
import { isIP } from 'node:net';
import { parseHsts } from '../../assets/js/lib/origincompare.js';
import { AbortError } from '../../assets/js/lib/util.js';

/** Time for one GET (each of the two). */
export const HTTP_TIMEOUT_MS = 10000;
/** The statuses of a redirect. */
export const REDIRECT_STATUSES = Object.freeze([301, 302, 303, 307, 308]);
/** A Location header is kept up to this many characters. */
const LOCATION_MAX = 200;
const USER_AGENT = 'domainscope-ds (+https://github.com/halilibrahimd27/domainscope)';

/** Why a GET got no answer, in a few words. */
function failure(err, timeoutMs) {
  const errCode = err && typeof err.code === 'string' ? err.code : '';
  if (errCode === 'ETIMEDOUT' || (err && err.name === 'TimeoutError')) return `no answer within ${Math.round(timeoutMs / 1000)} s`;
  if (errCode === 'ECONNREFUSED') return 'connection refused';
  if (errCode === 'ECONNRESET') return 'connection reset';
  if (errCode === 'HPE_INVALID_CONSTANT' || /^HPE_/.test(errCode)) return 'not an HTTP answer';
  const message = String((err && err.message) || err || 'error').replace(/\s+/g, ' ');
  return (errCode ? `${errCode}: ${message}` : message).slice(0, 120);
}

/**
 * One `GET /` (`options` for node:http request: a `createConnection` over an open socket, or a
 * host and port), resolving with the status and the headers once they arrive, or `{ error }`.
 * Rejects only on an abort.
 * @param {object} options
 * @param {{ timeoutMs?: number, request?: typeof http.request, signal?: AbortSignal }} [opts]
 * @returns {Promise<{ status: number, headers: Record<string, string|string[]> }|{ error: string }>}
 */
export function getHead(options, { timeoutMs = HTTP_TIMEOUT_MS, request = http.request, signal } = {}) {
  return new Promise((resolve, reject) => {
    if (signal && signal.aborted) {
      reject(new AbortError('The operation was aborted'));
      return;
    }
    let req = null;
    let done = false;
    const finish = (value, rejected = false) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      if (signal) signal.removeEventListener('abort', onAbort);
      try {
        if (req) req.destroy();
      } catch {
        /* already gone */
      }
      if (rejected) reject(value);
      else resolve(value);
    };
    const onAbort = () => finish(new AbortError('The operation was aborted'), true);
    const timer = setTimeout(() => finish({ error: failure({ code: 'ETIMEDOUT' }, timeoutMs) }), timeoutMs);
    if (signal) signal.addEventListener('abort', onAbort, { once: true });
    try {
      req = request({ method: 'GET', path: '/', ...options }, (res) => {
        finish({ status: res.statusCode, headers: { ...res.headers } });
        res.destroy();
      });
      req.on('error', (err) => finish({ error: failure(err, timeoutMs) }));
      req.end();
    } catch (err) {
      finish({ error: failure(err, timeoutMs) });
    }
  });
}

/** The `Host` header of a request to `host` (or an address) on `port`. */
export function hostHeader(host, address, port, defaultPort) {
  const name = host || (isIP(address) === 6 ? `[${address}]` : address);
  return port === defaultPort ? name : `${name}:${port}`;
}

/** The request headers of a GET. */
const headersFor = (host) => ({ Host: host, 'User-Agent': USER_AGENT, Accept: '*/*', 'Accept-Encoding': 'identity', Connection: 'close' });

/**
 * `GET /` over a TLS socket the handshake opened.
 * @param {import('node:tls').TLSSocket} socket
 * @param {{ host: string|null, address: string, port: number, timeoutMs?: number, request?: Function, signal?: AbortSignal }} opts
 */
export function getOverTls(socket, { host, address, port, timeoutMs, request, signal }) {
  return getHead({ createConnection: () => socket, headers: headersFor(hostHeader(host, address, port, 443)) }, { timeoutMs, request, signal });
}

/**
 * `GET /` over plain HTTP to port 80 of `address`.
 * @param {{ host: string|null, address: string, timeoutMs?: number, request?: Function, signal?: AbortSignal }} opts
 */
export function getPlain({ host, address, timeoutMs, request, signal }) {
  return getHead({ host: address, port: 80, agent: false, headers: headersFor(hostHeader(host, address, 80, 80)) }, { timeoutMs, request, signal });
}

/** A header's first value, or null. */
const header = (headers, name) => {
  const v = headers ? headers[name] : undefined;
  return Array.isArray(v) ? (v.length ? String(v[0]) : null) : typeof v === 'string' ? v : null;
};

/**
 * Does an answer redirect to https://? A redirect status whose Location, read against
 * `http://host/`, is an https URL.
 * @param {number|null} status
 * @param {string|null} location
 * @param {string} base the host the request named (`Host`)
 * @returns {boolean}
 */
export function redirectsToHttps(status, location, base) {
  if (!REDIRECT_STATUSES.includes(status) || typeof location !== 'string' || !location.trim()) return false;
  try {
    return new URL(location.trim(), `http://${base}/`).protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * What the report keeps of the two answers (`plain` undefined: not asked, a port other than 443).
 * @param {{ status?: number, headers?: object, error?: string }} secure the GET over TLS
 * @param {{ status?: number, headers?: object, error?: string }|undefined} plain the GET to port 80
 * @param {string} base the `Host` of the plain request
 * @returns {{ status: number|null, error: string|null, hsts: { maxAge: number|null, includeSubDomains: boolean, preload: boolean, valid: boolean }|null,
 *   plain: { status: number|null, location: string|null, toHttps: boolean, error: string|null }|null }}
 */
export function httpRecord(secure, plain, base) {
  const hsts = secure && Number.isInteger(secure.status) ? parseHsts(header(secure.headers, 'strict-transport-security')) : null;
  let p = null;
  if (plain) {
    const location = header(plain.headers, 'location');
    const status = Number.isInteger(plain.status) ? plain.status : null;
    p = {
      status,
      location: location ? location.trim().slice(0, LOCATION_MAX) : null,
      toHttps: redirectsToHttps(status, location, base),
      error: plain.error || null
    };
  }
  return {
    status: secure && Number.isInteger(secure.status) ? secure.status : null,
    error: (secure && secure.error) || null,
    hsts: hsts ? { maxAge: hsts.maxAge, includeSubDomains: hsts.includeSubDomains, preload: hsts.preload, valid: hsts.valid } : null,
    plain: p
  };
}
