/* ============================================================================
   Static file serving and access control.
   ========================================================================= */
'use strict';

const fs = require('fs');
const path = require('path');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.md': 'text/markdown; charset=utf-8'
};

/** Resolve a URL path inside root, refusing anything that escapes it. */
function resolveSafe(root, urlPath) {
  const decoded = decodeURIComponent(urlPath.split('?')[0]);
  const rel = decoded === '/' ? 'index.html' : decoded.replace(/^\/+/, '');
  const target = path.resolve(root, rel);
  const prefix = path.resolve(root) + path.sep;
  if (target !== path.resolve(root) && target.indexOf(prefix) !== 0) return null;
  return target;
}

function serve(res, root, urlPath) {
  const file = resolveSafe(root, urlPath);
  if (!file) { res.writeHead(403).end('Forbidden'); return; }

  fs.stat(file, (err, stat) => {
    if (err || !stat.isFile()) {
      // Unknown path with no extension: the hash router owns it, hand back
      // the shell so a deep link works after a reload.
      if (!path.extname(file)) { serve(res, root, '/index.html'); return; }
      res.writeHead(404, { 'Content-Type': 'text/plain' }).end('Not found');
      return;
    }
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream',
      'Content-Length': stat.size,
      'Cache-Control': 'no-cache',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer'
    });
    fs.createReadStream(file).pipe(res);
  });
}

/** Loopback callers are already on the machine running the scanner. */
function isLoopback(req) {
  const addr = req.socket.remoteAddress || '';
  return addr === '127.0.0.1' || addr === '::1' || addr === '::ffff:127.0.0.1';
}

/**
 * Constant-time token comparison. Length is compared first because
 * timingSafeEqual throws on a mismatch.
 */
function tokenMatches(expected, supplied) {
  if (!supplied || supplied.length !== expected.length) return false;
  const crypto = require('crypto');
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(supplied));
}

function extractToken(req, url) {
  const header = req.headers.authorization || '';
  if (header.indexOf('Bearer ') === 0) return header.slice(7).trim();
  return url.searchParams.get('t');
}

/** True when this request may use the API. */
function authorised(req, url, token) {
  if (!token) return true;              // --no-token was passed
  if (isLoopback(req)) return true;
  return tokenMatches(token, extractToken(req, url));
}

module.exports = { serve, resolveSafe, authorised, isLoopback, MIME };
