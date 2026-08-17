/* ============================================================================
   Real HTTP responses.

   Running outside the browser means the full response head is visible, which
   is what makes the header analysis worth anything on a third-party host.

   Cookie values are dropped at parse time. The analyzer judges attributes —
   Secure, HttpOnly, SameSite — and has no use for the value, so it is never
   put into a record that could be exported or persisted.
   ========================================================================= */
'use strict';

const http = require('http');
const https = require('https');

const MAX_BODY = 64 * 1024;
const UA = 'CheckerTracker/1.0 (authorized assessment)';

/**
 * Fetch one URL and describe the response.
 * Redirects are reported, not followed, so the redirect itself stays visible.
 */
function fetchHead(target, options) {
  const opts = options || {};
  const timeoutMs = opts.timeoutMs || 8000;

  return new Promise((resolve) => {
    let url;
    try { url = new URL(target); }
    catch (e) { resolve({ ok: false, reason: 'invalid-url' }); return; }

    const secure = url.protocol === 'https:';
    const lib = secure ? https : http;
    const started = Date.now();

    const req = lib.request({
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port || (secure ? 443 : 80),
      path: (url.pathname || '/') + (url.search || ''),
      method: 'GET',
      headers: { 'User-Agent': UA, Accept: '*/*', Connection: 'close' },
      timeout: timeoutMs,
      // Inspecting a host with a bad certificate is a legitimate outcome to
      // record, not a reason to abandon the probe. tls-probe.js reports the
      // certificate state separately.
      rejectUnauthorized: false,
      servername: /^[\d.]+$/.test(url.hostname) ? undefined : url.hostname
    }, (res) => {
      const chunks = [];
      let size = 0;

      res.on('data', (chunk) => {
        size += chunk.length;
        if (chunks.length * 0 + size <= MAX_BODY) chunks.push(chunk);
        else res.destroy();
      });

      const done = () => {
        const body = Buffer.concat(chunks).toString('utf8');
        resolve({
          ok: true,
          url: url.href,
          scheme: url.protocol.replace(':', ''),
          port: Number(url.port || (secure ? 443 : 80)),
          status: res.statusCode,
          statusText: res.statusMessage || null,
          httpVersion: res.httpVersion,
          headers: lowercaseHeaders(res.headers),
          cookies: parseCookies(res.headers['set-cookie']),
          redirect: res.headers.location || null,
          server: res.headers.server || null,
          title: extractTitle(body),
          elapsedMs: Date.now() - started
        });
      };

      res.on('end', done);
      res.on('close', done);
      res.on('error', () => resolve({ ok: false, reason: 'stream-error' }));
    });

    req.on('timeout', () => { req.destroy(); resolve({ ok: false, reason: 'timeout' }); });
    req.on('error', (err) => resolve({ ok: false, reason: (err && err.code) || 'error', message: err ? String(err.message) : null }));
    req.end();
  });
}

function lowercaseHeaders(raw) {
  const out = {};
  Object.keys(raw || {}).forEach((key) => {
    const value = raw[key];
    out[key.toLowerCase()] = Array.isArray(value) ? value.join(', ') : String(value);
  });
  // The individual Set-Cookie lines are represented by `cookies`; keeping the
  // joined header as well would carry the values back with it.
  delete out['set-cookie'];
  return out;
}

/**
 * Reduce Set-Cookie lines to name plus protective attributes.
 * The value is never copied out of this function.
 */
function parseCookies(lines) {
  if (!lines) return [];
  return (Array.isArray(lines) ? lines : [lines]).map((line) => {
    const parts = String(line).split(';');
    const eq = parts[0].indexOf('=');
    const name = (eq === -1 ? parts[0] : parts[0].slice(0, eq)).trim();
    const flags = parts.slice(1).map((p) => p.trim());
    const attr = (needle) => flags.find((f) => f.toLowerCase().indexOf(needle) === 0) || null;
    const sameSite = attr('samesite=');

    return {
      name,
      secure: flags.some((f) => f.toLowerCase() === 'secure'),
      httpOnly: flags.some((f) => f.toLowerCase() === 'httponly'),
      sameSite: sameSite ? sameSite.split('=')[1] : null,
      path: attr('path=') ? attr('path=').split('=')[1] : null,
      hostOnly: !attr('domain=')
    };
  });
}

function extractTitle(body) {
  if (!body) return null;
  const m = body.match(/<title[^>]*>([\s\S]{0,200}?)<\/title>/i);
  return m ? m[1].replace(/\s+/g, ' ').trim().slice(0, 120) || null : null;
}

/**
 * Probe an open port as a web service, shaped for CT's `asset.http` field.
 * HTTPS is tried first on TLS ports, otherwise plain HTTP.
 */
async function probeWeb(ip, port, options) {
  const opts = options || {};
  const scheme = opts.tls ? 'https' : 'http';
  const host = opts.hostname || ip;
  const authority = (port === 80 || port === 443) ? host : host + ':' + port;

  const res = await fetchHead(scheme + '://' + authority + '/', opts);
  if (!res.ok) return null;

  return {
    port,
    scheme: res.scheme,
    status: res.status,
    redirect: res.redirect,
    server: res.server,
    headers: res.headers,
    cookies: res.cookies,
    title: res.title
  };
}

module.exports = { fetchHead, probeWeb, parseCookies };
