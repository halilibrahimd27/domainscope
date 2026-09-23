#!/usr/bin/env node
/**
 * serve.mjs — tiny dependency-free static file server (local preview + E2E tests).
 *
 * CLI:  node tests/e2e/serve.mjs [port=8080] [--host 127.0.0.1] [--root <dir>] [--base /prefix/] [--quiet]
 *   --base serves the site under a path prefix, e.g. `--base /subdomain-scanner/` to mimic a
 *   GitHub Pages project site (catches absolute asset URLs that would break there).
 *
 * API:  const srv = await startServer({ port: 0, base: '/subdomain-scanner/' });
 *       srv.url  // 'http://127.0.0.1:53211/subdomain-scanner/'
 *       await srv.close();
 *
 * Security: binds to 127.0.0.1 by default, GET/HEAD only, refuses path traversal and
 * symlink escapes, hides dot-files (except .nojekyll / .well-known), sends nosniff.
 */

import http from 'node:http';
import { createReadStream } from 'node:fs';
import { stat, realpath } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
/** Repository root (two levels above tests/e2e). */
export const REPO_ROOT = path.resolve(HERE, '..', '..');

/** Extension → Content-Type. Python/PEM files are served as text so they display and download cleanly. */
export const MIME_TYPES = Object.freeze({
  '.html': 'text/html; charset=utf-8',
  '.htm': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.cjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.avif': 'image/avif',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
  '.md': 'text/markdown; charset=utf-8',
  '.py': 'text/plain; charset=utf-8',
  '.pem': 'text/plain; charset=utf-8',
  '.crt': 'text/plain; charset=utf-8',
  '.csv': 'text/csv; charset=utf-8',
  '.xml': 'application/xml; charset=utf-8',
  '.pdf': 'application/pdf',
  '.wasm': 'application/wasm'
});

const ALLOWED_DOT = new Set(['.nojekyll', '.well-known']);

/**
 * Content-Type for a file name ('application/octet-stream' when unknown).
 * @param {string} file
 * @returns {string}
 */
export function contentType(file) {
  return MIME_TYPES[path.extname(file).toLowerCase()] || 'application/octet-stream';
}

function normalizeBase(base) {
  let b = String(base || '/').trim();
  if (!b.startsWith('/')) b = `/${b}`;
  if (!b.endsWith('/')) b = `${b}/`;
  return b.replace(/\/{2,}/g, '/');
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...headers
  });
  res.end(body);
}

/**
 * Map a request path to a file inside `root`, or null when it must not be served.
 * @param {string} root absolute, real path
 * @param {string} rel URL path relative to the base, already percent-decoded
 * @returns {string|null}
 */
export function resolveSafe(root, rel) {
  if (rel.includes('\0')) return null;
  const segments = rel.split('/').filter(Boolean);
  if (segments.some((s) => s === '..' || (s.startsWith('.') && !ALLOWED_DOT.has(s)))) return null;
  const full = path.resolve(root, ...segments);
  if (full !== root && !full.startsWith(root + path.sep)) return null;
  return full;
}

/**
 * Start the server.
 * @param {{ root?: string, port?: number, host?: string, base?: string, quiet?: boolean, headers?: object }} [opts]
 * @returns {Promise<{ server: http.Server, url: string, origin: string, port: number, close(): Promise<void> }>}
 */
export async function startServer({ root = REPO_ROOT, port = 0, host = '127.0.0.1', base = '/', quiet = true, headers = {} } = {}) {
  const realRoot = await realpath(path.resolve(root));
  const prefix = normalizeBase(base);

  const server = http.createServer(async (req, res) => {
    const started = Date.now();
    const done = (status) => {
      if (!quiet) process.stdout.write(`${new Date().toISOString().slice(11, 19)} ${status} ${req.method} ${req.url} ${Date.now() - started}ms\n`);
    };
    try {
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        send(res, 405, 'Method Not Allowed', { Allow: 'GET, HEAD' });
        return done(405);
      }
      const url = new URL(req.url || '/', 'http://localhost');
      let pathname;
      try {
        pathname = decodeURIComponent(url.pathname);
      } catch {
        send(res, 400, 'Bad Request');
        return done(400);
      }
      if (prefix !== '/') {
        if (`${pathname}/` === prefix) {
          send(res, 301, '', { Location: prefix + url.search });
          return done(301);
        }
        if (!pathname.startsWith(prefix)) {
          send(res, 404, `Not Found (site is served under ${prefix})`);
          return done(404);
        }
      }
      const rel = pathname.slice(prefix.length - 1);
      let file = resolveSafe(realRoot, rel);
      if (!file) {
        send(res, 404, 'Not Found');
        return done(404);
      }
      let info;
      try {
        info = await stat(file);
        if (info.isDirectory()) {
          if (!pathname.endsWith('/')) {
            send(res, 301, '', { Location: `${pathname}/${url.search}` });
            return done(301);
          }
          file = path.join(file, 'index.html');
          info = await stat(file);
        }
        // Refuse symlinks that point outside the root.
        const real = await realpath(file);
        if (real !== realRoot && !real.startsWith(realRoot + path.sep)) throw new Error('outside root');
      } catch {
        send(res, 404, 'Not Found');
        return done(404);
      }
      res.writeHead(200, {
        'Content-Type': contentType(file),
        'Content-Length': info.size,
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        ...headers
      });
      if (req.method === 'HEAD') {
        res.end();
        return done(200);
      }
      createReadStream(file).on('error', () => res.destroy()).pipe(res);
      return done(200);
    } catch (err) {
      if (!res.headersSent) send(res, 500, 'Internal Server Error');
      else res.destroy();
      return done(500);
    }
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, resolve);
  });
  const actualPort = server.address().port;
  const origin = `http://${host.includes(':') ? `[${host}]` : host}:${actualPort}`;
  return {
    server,
    port: actualPort,
    origin,
    url: `${origin}${prefix}`,
    close: () => new Promise((resolve) => {
      server.closeAllConnections?.();
      server.close(() => resolve());
    })
  };
}

function parseArgs(argv) {
  const opts = { port: 8080, host: '127.0.0.1', root: REPO_ROOT, base: '/', quiet: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--host') opts.host = argv[++i];
    else if (a === '--root') opts.root = path.resolve(argv[++i]);
    else if (a === '--base') opts.base = argv[++i];
    else if (a === '--quiet' || a === '-q') opts.quiet = true;
    else if (a === '--port' || a === '-p') opts.port = Number(argv[++i]);
    else if (/^\d+$/.test(a)) opts.port = Number(a);
    else if (a === '--help' || a === '-h') {
      process.stdout.write('Usage: node tests/e2e/serve.mjs [port=8080] [--host 127.0.0.1] [--root dir] [--base /prefix/] [--quiet]\n');
      process.exit(0);
    } else {
      process.stderr.write(`Unknown argument: ${a}\n`);
      process.exit(2);
    }
  }
  return opts;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const opts = parseArgs(process.argv.slice(2));
  startServer(opts).then((srv) => {
    process.stdout.write(`Serving ${opts.root} at ${srv.url}  (Ctrl+C to stop)\n`);
    const stop = () => srv.close().then(() => process.exit(0));
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
  }).catch((err) => {
    process.stderr.write(`serve.mjs: ${err.message}\n`);
    process.exit(1);
  });
}
