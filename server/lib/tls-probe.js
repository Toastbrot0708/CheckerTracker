/* ============================================================================
   Real TLS handshakes.

   Certificate validation is switched off throughout this file, and that is
   the point: an expired or self-signed certificate is exactly what an
   assessment needs to see. No data is ever written to these sockets — they
   are opened, inspected and closed — so there is nothing to intercept.
   ========================================================================= */
'use strict';

const tls = require('tls');

const VERSIONS = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'];

/**
 * Complete one handshake and report what the peer presented.
 *
 * @param {string} host        address to connect to
 * @param {number} port
 * @param {object} [options]   servername, timeoutMs, version
 */
function handshake(host, port, options) {
  const opts = options || {};
  const timeoutMs = opts.timeoutMs || 6000;

  return new Promise((resolve) => {
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      try { socket.destroy(); } catch (e) { /* already gone */ }
      resolve(value);
    };

    const config = {
      host,
      port,
      rejectUnauthorized: false,
      timeout: timeoutMs,
      ALPNProtocols: ['h2', 'http/1.1']
    };
    // SNI only when we have a real name; sending an IP literal is invalid.
    if (opts.servername && !/^[\d.]+$/.test(opts.servername)) config.servername = opts.servername;
    if (opts.version) {
      config.minVersion = opts.version;
      config.maxVersion = opts.version;
      // OpenSSL 3 refuses legacy versions at the default security level. This
      // relaxation exists solely so the old versions can be *tested for*.
      if (opts.version === 'TLSv1' || opts.version === 'TLSv1.1') {
        config.ciphers = 'DEFAULT:@SECLEVEL=0';
      }
    }

    const socket = tls.connect(config, () => {
      const peer = socket.getPeerCertificate(true);
      const cipher = socket.getCipher() || {};
      finish({
        ok: true,
        protocol: socket.getProtocol(),
        cipher: cipher.name || null,
        cipherStandard: cipher.standardName || null,
        cipherVersion: cipher.version || null,
        alpn: socket.alpnProtocol || null,
        authorized: socket.authorized,
        authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
        certDer: derOf(peer),
        chainDer: chainOf(peer),
        chainLength: chainOf(peer).length + 1
      });
    });

    socket.once('timeout', () => finish({ ok: false, reason: 'timeout' }));
    socket.once('error', (err) => finish({
      ok: false,
      reason: (err && err.code) || 'error',
      message: err ? String(err.message) : null
    }));
  });
}

function derOf(cert) {
  return cert && cert.raw ? cert.raw.toString('base64') : null;
}

/** Intermediates the peer sent, stopping at the self-signed root. */
function chainOf(cert) {
  const out = [];
  let node = cert && cert.issuerCertificate;
  const seen = new Set();
  while (node && node.raw) {
    const key = node.fingerprint256 || node.raw.toString('base64').slice(0, 64);
    if (seen.has(key)) break;          // self-signed roots point at themselves
    seen.add(key);
    out.push(node.raw.toString('base64'));
    if (out.length >= 8) break;
    node = node.issuerCertificate;
  }
  return out;
}

/**
 * Determine which protocol versions the peer will negotiate.
 *
 * Three outcomes per version, kept distinct. "untestable" means this Node
 * build would not offer the version, which is a statement about the scanner
 * and not about the target — collapsing it into "unsupported" would be a
 * result we did not actually observe.
 */
async function enumerateProtocols(host, port, options) {
  const opts = options || {};
  const accepted = [];
  const refused = [];
  const untestable = [];

  for (const version of VERSIONS) {
    const result = await handshake(host, port, {
      servername: opts.servername,
      timeoutMs: opts.timeoutMs || 4000,
      version
    });
    if (result.ok) { accepted.push(version); continue; }
    if (isLocalRefusal(result)) untestable.push(version);
    else refused.push(version);
  }

  return { accepted, refused, untestable };
}

/* Errors raised by our own OpenSSL before anything reached the network. */
function isLocalRefusal(result) {
  const text = ((result.reason || '') + ' ' + (result.message || '')).toLowerCase();
  return text.indexOf('no protocols available') !== -1 ||
         text.indexOf('unsupported protocol') !== -1 ||
         text.indexOf('version too low') !== -1 ||
         text.indexOf('no ciphers available') !== -1 ||
         text.indexOf('err_ssl_version') !== -1;
}

/**
 * Full inspection of one TLS endpoint, shaped for CT's `asset.tls` field.
 * `cert` stays as DER; the client decodes it with CT.crypto.parseCertificate.
 */
async function inspect(host, port, options) {
  const opts = options || {};
  const primary = await handshake(host, port, opts);
  if (!primary.ok) return { port, reachable: false, reason: primary.reason, message: primary.message || null };

  const protocols = opts.enumerate === false
    ? { accepted: primary.protocol ? [primary.protocol] : [], refused: [], untestable: VERSIONS }
    : await enumerateProtocols(host, port, opts);

  return {
    port,
    reachable: true,
    negotiated: primary.protocol,
    protocols: protocols.accepted,
    protocolsRefused: protocols.refused,
    protocolsUntestable: protocols.untestable,
    minProtocol: protocols.accepted.length ? protocols.accepted[0] : primary.protocol,
    cipher: primary.cipherStandard || primary.cipher,
    alpn: primary.alpn,
    trusted: primary.authorized,
    trustError: primary.authorizationError,
    chainLength: primary.chainLength,
    certDer: primary.certDer,
    chainDer: primary.chainDer
  };
}

module.exports = { VERSIONS, handshake, enumerateProtocols, inspect };
