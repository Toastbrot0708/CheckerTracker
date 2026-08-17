/* ============================================================================
   TCP probing: liveness, open ports, service banners.

   Ordinary connect() scanning. The handshake completes and the socket closes
   cleanly, which is visible in any target's logs — deliberately so. This is
   an assessment tool and it does not hide.
   ========================================================================= */
'use strict';

const net = require('net');
const { pool } = require('./pool');

/* Ports checked to decide whether an address is alive at all. Chosen because
   something answers on at least one of them on almost any real device. */
const LIVENESS_PORTS = [80, 443, 22, 445, 139, 53, 8080, 3389, 631, 62078];

const TOP_PORTS = [
  21, 22, 23, 25, 53, 67, 80, 81, 88, 110, 111, 123, 135, 137, 138, 139, 143,
  161, 389, 443, 445, 465, 500, 515, 548, 554, 587, 631, 636, 873, 902, 993,
  995, 1023, 1080, 1194, 1433, 1521, 1723, 1883, 1900, 2049, 2082, 2083, 2086,
  2181, 2375, 2376, 3000, 3128, 3260, 3268, 3306, 3389, 4443, 4444, 5000, 5001,
  5060, 5061, 5222, 5353, 5432, 5555, 5601, 5672, 5900, 5901, 5985, 5986, 6379,
  6443, 7000, 7001, 8000, 8006, 8008, 8009, 8080, 8081, 8086, 8088, 8123, 8443,
  8500, 8888, 9000, 9090, 9092, 9100, 9200, 9300, 10000, 11211, 27017, 32400,
  49152, 51820, 62078
];

/* Services that greet the client without being asked. */
const SPEAKS_FIRST = new Set([21, 22, 23, 25, 110, 143, 587, 3306, 5222, 6667]);

/* Ports where an unencrypted HTTP request is the right nudge. */
const HTTP_PORTS = new Set([
  80, 81, 88, 591, 2082, 2086, 3000, 3128, 5000, 5001, 5601, 7000, 7001, 8000,
  8006, 8008, 8080, 8081, 8086, 8088, 8123, 8500, 8888, 9000, 9090, 9200, 10000, 32400
]);

/* Ports that speak TLS immediately; handled by tls-probe.js instead. */
const TLS_PORTS = new Set([443, 465, 636, 989, 990, 993, 995, 2083, 2087, 4443, 5061, 5986, 6443, 8443, 9443]);

/**
 * Probe one TCP port.
 * @returns {Promise<{port:number,state:'open'|'closed'|'filtered',rttMs:number}>}
 */
function probePort(ip, port, timeoutMs) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    const started = Date.now();
    let settled = false;

    const finish = (state) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ port, state, rttMs: Date.now() - started });
    };

    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish('open'));
    socket.once('timeout', () => finish('filtered'));
    socket.once('error', (err) => {
      // A refusal is a reply: the host is up, this port is shut.
      // Anything else (unreachable, reset by an intermediary) is inconclusive.
      finish(err && err.code === 'ECONNREFUSED' ? 'closed' : 'filtered');
    });

    try { socket.connect(port, ip); } catch (e) { finish('filtered'); }
  });
}

/**
 * Decide whether an address is alive, using TCP alone.
 * Either an accepted or a refused connection proves presence.
 */
async function probeLiveness(ip, options) {
  const opts = options || {};
  const timeout = opts.timeoutMs || 700;
  const results = await pool(
    opts.ports || LIVENESS_PORTS, 8,
    (port) => probePort(ip, port, timeout), opts.control
  );

  const seen = results.filter(Boolean);
  const open = seen.filter((r) => r.state === 'open');
  const closed = seen.filter((r) => r.state === 'closed');
  const alive = open.length > 0 || closed.length > 0;

  return {
    ip,
    alive,
    evidence: open.length ? 'tcp-open' : closed.length ? 'tcp-refused' : null,
    openPorts: open.map((r) => r.port),
    rttMs: seen.length ? Math.min.apply(null, seen.map((r) => r.rttMs)) : null
  };
}

/** Full port sweep of one host. */
async function scanPorts(ip, ports, options) {
  const opts = options || {};
  const timeout = opts.timeoutMs || 900;
  const results = (await pool(ports, opts.concurrency || 24,
    (port) => probePort(ip, port, timeout), opts.control)).filter(Boolean);

  return {
    open: results.filter((r) => r.state === 'open').map((r) => r.port),
    closed: results.filter((r) => r.state === 'closed').length,
    filtered: results.filter((r) => r.state === 'filtered').length,
    tested: results.length
  };
}

/**
 * Read whatever a service volunteers. Servers that greet first are simply
 * listened to; HTTP ports get a HEAD request identifying the scanner.
 * Nothing resembling a credential is ever sent.
 */
function grabBanner(ip, port, timeoutMs) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    const chunks = [];
    let settled = false;
    let nudged = false;

    const finish = () => {
      if (settled) return;
      settled = true;
      socket.destroy();
      const text = Buffer.concat(chunks).toString('latin1').trim();
      resolve(text ? text.slice(0, 1024) : null);
    };

    const nudge = () => {
      if (nudged || !HTTP_PORTS.has(port)) { finish(); return; }
      nudged = true;
      socket.write(
        'HEAD / HTTP/1.0\r\n' +
        'Host: ' + ip + '\r\n' +
        'User-Agent: CheckerTracker/1.0 (authorized assessment)\r\n' +
        'Connection: close\r\n\r\n'
      );
      setTimeout(finish, timeoutMs);
    };

    socket.setTimeout(timeoutMs * 2);
    socket.once('connect', () => {
      if (SPEAKS_FIRST.has(port)) setTimeout(() => (chunks.length ? finish() : nudge()), timeoutMs);
      else nudge();
    });
    socket.on('data', (chunk) => {
      chunks.push(chunk);
      if (Buffer.concat(chunks).length > 4096) finish();
    });
    socket.once('close', finish);
    socket.once('timeout', finish);
    socket.once('error', finish);

    try { socket.connect(port, ip); } catch (e) { finish(); }
  });
}

/* Patterns matched against banners a service actually returned. No match
   means no claim: product and version stay null. */
const BANNER_PATTERNS = [
  { re: /^SSH-[\d.]+-OpenSSH[_-]([\w.]+)/i, product: 'OpenSSH', version: 1 },
  { re: /^SSH-[\d.]+-(dropbear[_-]?([\w.]*))/i, product: 'Dropbear', version: 2 },
  { re: /^SSH-[\d.]+-(.+)$/im, product: 1, version: null },
  { re: /^220[- ].*?Postfix/im, product: 'Postfix', version: null },
  { re: /^220[- ].*?Exim ([\w.]+)/im, product: 'Exim', version: 1 },
  { re: /^220[- ]([\w.-]+) FTP/im, product: 'FTP', version: null },
  { re: /^220[- ].*?vsFTPd ([\w.]+)/im, product: 'vsftpd', version: 1 },
  { re: /^Server:\s*nginx\/([\w.]+)/im, product: 'nginx', version: 1 },
  { re: /^Server:\s*nginx/im, product: 'nginx', version: null },
  { re: /^Server:\s*Apache\/([\w.]+)/im, product: 'Apache httpd', version: 1 },
  { re: /^Server:\s*Apache/im, product: 'Apache httpd', version: null },
  { re: /^Server:\s*Microsoft-IIS\/([\w.]+)/im, product: 'Microsoft IIS', version: 1 },
  { re: /^Server:\s*lighttpd\/([\w.]+)/im, product: 'lighttpd', version: 1 },
  { re: /^Server:\s*CUPS\/([\w.]+)/im, product: 'CUPS', version: 1 },
  { re: /^Server:\s*(.+)$/im, product: 1, version: null },
  { re: /^\+OK.*?Dovecot/im, product: 'Dovecot', version: null },
  { re: /([\d.]+)-MariaDB/i, product: 'MariaDB', version: 1 },
  { re: /^.\x00\x00\x00\n([\d.]+)/, product: 'MySQL', version: 1 }
];

function identifyBanner(banner) {
  if (!banner) return { product: null, version: null, confidence: null };
  for (const rule of BANNER_PATTERNS) {
    const m = banner.match(rule.re);
    if (!m) continue;
    const product = typeof rule.product === 'number' ? String(m[rule.product]).trim() : rule.product;
    const version = rule.version ? (m[rule.version] || null) : null;
    return {
      product: product ? product.slice(0, 80) : null,
      version: version ? String(version).slice(0, 40) : null,
      confidence: version ? 'high' : 'medium'
    };
  }
  return { product: null, version: null, confidence: null };
}

module.exports = {
  LIVENESS_PORTS, TOP_PORTS, TLS_PORTS, HTTP_PORTS,
  probePort, probeLiveness, scanPorts, grabBanner, identifyBanner
};
