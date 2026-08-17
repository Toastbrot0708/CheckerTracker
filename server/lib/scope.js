/* ============================================================================
   Scope parsing and enforcement.

   Mirrors CT.net on the client, but this copy is the one that matters: the
   browser can be bypassed, this cannot.
   ========================================================================= */
'use strict';

const MAX_PREFIX = 16;        // nothing broader than a /16
const MAX_ADDRESSES = 65536;

/* Ranges an assessment may touch without an explicit override. */
const SAFE_RANGES = [
  ['10.0.0.0', 8, 'RFC 1918 private'],
  ['172.16.0.0', 12, 'RFC 1918 private'],
  ['192.168.0.0', 16, 'RFC 1918 private'],
  ['100.64.0.0', 10, 'RFC 6598 carrier-grade NAT'],
  ['169.254.0.0', 16, 'RFC 3927 link-local'],
  ['127.0.0.0', 8, 'loopback']
];

function ipToInt(ip) {
  const parts = String(ip).trim().split('.');
  if (parts.length !== 4) throw new Error('Not an IPv4 address: ' + ip);
  let n = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) throw new Error('Not an IPv4 address: ' + ip);
    const octet = Number(part);
    if (octet > 255) throw new Error('Octet out of range: ' + ip);
    n = (n * 256) + octet;
  }
  return n >>> 0;
}

function intToIp(value) {
  const n = value >>> 0;
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

function maskFor(prefix) {
  return prefix === 0 ? 0 : ((0xFFFFFFFF << (32 - prefix)) >>> 0);
}

function rangeOf(ip, prefix) {
  const mask = maskFor(prefix);
  const network = (ipToInt(ip) & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  return { network, broadcast, mask };
}

/** Which safe range an address falls in, or null if it is outside all of them. */
function safeRangeOf(ip) {
  const value = ipToInt(ip);
  for (const [base, prefix, label] of SAFE_RANGES) {
    const { network, broadcast } = rangeOf(base, prefix);
    if (value >= network && value <= broadcast) return label;
  }
  return null;
}

function cidrInfo(text) {
  const raw = String(text).trim();
  const slash = raw.indexOf('/');
  const addr = slash === -1 ? raw : raw.slice(0, slash);
  const prefix = slash === -1 ? 32 : Number(raw.slice(slash + 1));

  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    throw new Error('Prefix must be between /0 and /32: ' + raw);
  }
  const { network, broadcast, mask } = rangeOf(addr, prefix);
  const total = broadcast - network + 1;

  return {
    input: raw,
    prefix,
    network: intToIp(network),
    broadcast: intToIp(broadcast),
    netmask: intToIp(mask),
    firstHost: intToIp(prefix >= 31 ? network : network + 1),
    lastHost: intToIp(prefix >= 31 ? broadcast : broadcast - 1),
    totalAddresses: total,
    usableHosts: prefix >= 31 ? total : Math.max(0, total - 2),
    safeRange: safeRangeOf(intToIp(network))
  };
}

/**
 * Parse an operator-supplied scope into the exact address list that may be
 * touched. Comma separated: CIDR blocks, single addresses, or a-b ranges.
 *
 * @param {string} text
 * @param {{allowPublic?: boolean}} [options]
 */
function parseScope(text, options) {
  const opts = options || {};
  const pieces = String(text || '').split(',').map((s) => s.trim()).filter(Boolean);
  if (!pieces.length) throw scopeError('No scope was supplied.');

  const entries = [];
  const seen = new Set();
  const addresses = [];

  for (const piece of pieces) {
    let first;
    let last;
    let info = null;

    const dash = piece.indexOf('-');
    if (dash !== -1 && piece.indexOf('/') === -1) {
      first = ipToInt(piece.slice(0, dash).trim());
      last = ipToInt(piece.slice(dash + 1).trim());
      if (last < first) throw scopeError('Range runs backwards: ' + piece);
    } else {
      info = cidrInfo(piece);
      if (info.prefix < MAX_PREFIX) {
        throw scopeError('Scope ' + piece + ' is broader than /' + MAX_PREFIX +
          '. Narrow it to the segment you are authorized to assess.');
      }
      first = ipToInt(info.network);
      last = ipToInt(info.broadcast);
      // A /31 or /32 addresses every value; anything wider excludes network
      // and broadcast, which are not hosts.
      if (info.prefix < 31) { first += 1; last -= 1; }
    }

    const count = last - first + 1;
    if (count <= 0) throw scopeError('Scope ' + piece + ' contains no usable address.');

    for (let value = first; value <= last; value++) {
      const ip = intToIp(value);
      if (!opts.allowPublic && !safeRangeOf(ip)) {
        throw scopeError('Address ' + ip + ' is outside private address space. ' +
          'Start the service with --allow-public to assess routable addresses, ' +
          'and only with written authorization for those systems.');
      }
      if (seen.has(ip)) continue;
      seen.add(ip);
      addresses.push(ip);
      if (addresses.length > MAX_ADDRESSES) {
        throw scopeError('Scope exceeds ' + MAX_ADDRESSES + ' addresses.');
      }
    }

    entries.push({ input: piece, info, first: intToIp(first), last: intToIp(last), count });
  }

  return {
    label: entries.map((e) => e.input).join(', '),
    entries,
    addresses,
    total: addresses.length,
    contains: (ip) => seen.has(ip)
  };
}

function scopeError(message) {
  const e = new Error(message);
  e.code = 'SCOPE';
  return e;
}

module.exports = {
  MAX_PREFIX, MAX_ADDRESSES, SAFE_RANGES,
  ipToInt, intToIp, maskFor, cidrInfo, safeRangeOf, parseScope
};
