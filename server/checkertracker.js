#!/usr/bin/env node
/* ============================================================================
   CheckerTracker scanner service.

     node server/checkertracker.js
     node server/checkertracker.js --tls --port 8899

   Node 18 or newer. No dependencies.
   ========================================================================= */
'use strict';

const http = require('http');
const https = require('https');
const os = require('os');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const api = require('./lib/http-api');
const statics = require('./lib/static');

const ROOT = path.resolve(__dirname, '..');

function parseArgs(argv) {
  const out = { port: 8899, host: '0.0.0.0', allowPublic: false, tls: false, token: true };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--port') out.port = Number(argv[++i]) || out.port;
    else if (arg === '--host') out.host = argv[++i] || out.host;
    else if (arg === '--allow-public') out.allowPublic = true;
    else if (arg === '--tls') out.tls = true;
    else if (arg === '--no-token') out.token = false;
    else if (arg === '--help' || arg === '-h') out.help = true;
  }
  return out;
}

const HELP = [
  'CheckerTracker scanner service',
  '',
  '  --port <n>       listen port (default 8899)',
  '  --host <addr>    bind address (default 0.0.0.0, needed for phone access)',
  '  --tls            serve HTTPS with a generated self-signed certificate',
  '  --allow-public   permit scanning outside private address space',
  '  --no-token       disable API authentication (localhost testing only)',
  ''
].join('\n');

/**
 * Self-signed certificate for LAN use. Generated fresh on each start and
 * kept in memory only — it exists to make the page a secure context, not to
 * assert an identity, and writing a private key to disk would contradict
 * everything else this project says about key material.
 */
function generateCert() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ct-tls-'));
  const keyFile = path.join(dir, 'key.pem');
  const certFile = path.join(dir, 'cert.pem');
  try {
    execFileSync('openssl', [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', keyFile, '-out', certFile,
      '-days', '30', '-subj', '/CN=checkertracker.local'
    ], { stdio: 'ignore' });
    const pair = { key: fs.readFileSync(keyFile), cert: fs.readFileSync(certFile) };
    fs.rmSync(dir, { recursive: true, force: true });
    return pair;
  } catch (e) {
    fs.rmSync(dir, { recursive: true, force: true });
    return null;
  }
}

function lanAddresses() {
  const out = [];
  const nics = os.networkInterfaces();
  Object.keys(nics).forEach((name) => {
    (nics[name] || []).forEach((entry) => {
      if ((entry.family === 'IPv4' || entry.family === 4) && !entry.internal) out.push(entry.address);
    });
  });
  return out;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) { process.stdout.write(HELP); return; }

  const token = args.token ? crypto.randomBytes(16).toString('hex') : null;
  const audit = [];
  const auditLog = (action, detail) => {
    const entry = { ts: new Date().toISOString(), action, detail };
    audit.push(entry);
    if (audit.length > 2000) audit.shift();
    process.stdout.write('[' + entry.ts + '] ' + action + '  ' + detail + '\n');
  };

  let credentials = null;
  if (args.tls) {
    credentials = generateCert();
    if (!credentials) {
      process.stderr.write(
        'openssl was not available, so HTTPS could not be enabled.\n' +
        'Continuing over HTTP. The app will report the encrypted vault and\n' +
        'WebCrypto hashing as unavailable, which over plain HTTP they are.\n\n');
    }
  }

  const onRequest = async (req, res) => {
    const url = new URL(req.url, 'http://' + (req.headers.host || 'localhost'));

    if (url.pathname.indexOf('/api') === 0) {
      if (!statics.authorised(req, url, token)) {
        api.json(res, 401, {
          error: 'unauthorized',
          message: 'A valid access token is required. Open the URL printed by the service.'
        });
        return;
      }
      try {
        await api.handle(req, res, url, { allowPublic: args.allowPublic, tls: !!credentials, auditLog });
      } catch (err) {
        if (!res.headersSent) api.json(res, 500, { error: 'internal', message: String(err && err.message) });
      }
      return;
    }

    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { Allow: 'GET, HEAD' }).end();
      return;
    }
    statics.serve(res, ROOT, url.pathname);
  };

  const server = credentials
    ? https.createServer(credentials, onRequest)
    : http.createServer(onRequest);

  server.on('clientError', (err, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
  });

  server.listen(args.port, args.host, () => {
    const scheme = credentials ? 'https' : 'http';
    const query = token ? '/?t=' + token : '/';

    process.stdout.write('\nCheckerTracker scanner service\n');
    process.stdout.write('  scanning        ' +
      (args.allowPublic ? 'private and public addresses' : 'private address space only') + '\n');
    process.stdout.write('  api auth        ' + (token ? 'token required' : 'DISABLED (--no-token)') + '\n');
    process.stdout.write('  secure context  ' + (credentials
      ? 'yes — encrypted vault and hashing available'
      : 'no — vault and SHA hashing will report as unavailable') + '\n\n');

    process.stdout.write('  On this machine:\n    ' + scheme + '://localhost:' + args.port + '/\n\n');
    const lan = lanAddresses();
    if (lan.length) {
      process.stdout.write('  From your phone on the same network:\n');
      lan.forEach((addr) => process.stdout.write('    ' + scheme + '://' + addr + ':' + args.port + query + '\n'));
      process.stdout.write('\n');
    }
    if (credentials) {
      process.stdout.write('  The certificate is self-signed, so the browser will warn once.\n' +
        '  That is expected on a LAN address and safe to accept here.\n\n');
    }
    process.stdout.write('  Assess only networks you own or are authorized to test.\n' +
      '  Ctrl+C to stop.\n\n');
  });

  server.on('error', (err) => {
    if (err && err.code === 'EADDRINUSE') {
      process.stderr.write('Port ' + args.port + ' is already in use. Try --port 8900.\n');
      process.exit(1);
    }
    throw err;
  });
}

main();
