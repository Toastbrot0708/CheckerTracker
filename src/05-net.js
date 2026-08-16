/* ============================================================================
   MODULE: CT.net — IPv4/CIDR mathematics and scope parsing (fully real)
   ========================================================================= */
CT.net = (function () {
  'use strict';

  const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

  function isIPv4(s) {
    const m = IPV4_RE.exec(String(s).trim());
    if (!m) return false;
    for (let i = 1; i <= 4; i++) {
      const v = Number(m[i]);
      if (v > 255) return false;
      if (m[i].length > 1 && m[i][0] === '0') return false;
    }
    return true;
  }

  function ipToInt(ip) {
    const p = String(ip).trim().split('.');
    return (((+p[0] << 24) >>> 0) + (+p[1] << 16) + (+p[2] << 8) + (+p[3])) >>> 0;
  }
  function intToIp(n) {
    n = n >>> 0;
    return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
  }
  function maskFromPrefix(bits) {
    return bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
  }
  function prefixFromMask(mask) {
    let bits = 0, m = ipToInt(mask);
    for (let i = 31; i >= 0; i--) { if (m & (1 << i)) bits++; else break; }
    return bits;
  }

  /** Parse "a.b.c.d/nn" (or a bare address, treated as /32). */
  function parseCidr(input) {
    const s = String(input).trim();
    const parts = s.split('/');
    const ip = parts[0];
    if (!isIPv4(ip)) throw new Error('Invalid IPv4 address: "' + ip + '"');
    let bits = 32;
    if (parts.length > 1) {
      if (!/^\d{1,2}$/.test(parts[1])) throw new Error('Invalid prefix length: "/' + parts[1] + '"');
      bits = Number(parts[1]);
      if (bits < 0 || bits > 32) throw new Error('Prefix length must be between /0 and /32');
    }
    if (parts.length > 2) throw new Error('Malformed CIDR notation');
    return { ip, bits };
  }

  /** Full derived facts for a CIDR block. */
  function cidrInfo(input) {
    const { ip, bits } = parseCidr(input);
    const addr = ipToInt(ip);
    const mask = maskFromPrefix(bits);
    const network = (addr & mask) >>> 0;
    const broadcast = (network | (~mask >>> 0)) >>> 0;
    const total = bits === 32 ? 1 : Math.pow(2, 32 - bits);
    let usable, firstHost, lastHost;
    if (bits >= 31) { usable = bits === 32 ? 1 : 2; firstHost = network; lastHost = broadcast; }
    else { usable = total - 2; firstHost = network + 1; lastHost = broadcast - 1; }
    return {
      input: s0(ip, bits), address: ip, prefix: bits,
      netmask: intToIp(mask), wildcard: intToIp(~mask >>> 0),
      network: intToIp(network), broadcast: intToIp(broadcast),
      firstHost: intToIp(firstHost), lastHost: intToIp(lastHost),
      totalAddresses: total, usableHosts: usable,
      networkInt: network, broadcastInt: broadcast,
      isPrivate: isPrivate(ip), class: addrClass(addr),
      rangeLabel: intToIp(firstHost) + ' – ' + intToIp(lastHost)
    };
  }
  function s0(ip, bits) { return ip + '/' + bits; }

  function addrClass(n) {
    const first = (n >>> 24) & 255;
    if (first < 128) return 'A';
    if (first < 192) return 'B';
    if (first < 224) return 'C';
    if (first < 240) return 'D (multicast)';
    return 'E (reserved)';
  }

  function isPrivate(ip) {
    const n = ipToInt(ip);
    return (n >= ipToInt('10.0.0.0') && n <= ipToInt('10.255.255.255')) ||
           (n >= ipToInt('172.16.0.0') && n <= ipToInt('172.31.255.255')) ||
           (n >= ipToInt('192.168.0.0') && n <= ipToInt('192.168.255.255'));
  }
  function isLoopback(ip) { const n = ipToInt(ip); return n >= ipToInt('127.0.0.0') && n <= ipToInt('127.255.255.255'); }
  function isLinkLocal(ip) { const n = ipToInt(ip); return n >= ipToInt('169.254.0.0') && n <= ipToInt('169.254.255.255'); }

  function ipInCidr(ip, cidr) {
    const info = parseCidr(cidr);
    const mask = maskFromPrefix(info.bits);
    return ((ipToInt(ip) & mask) >>> 0) === ((ipToInt(info.ip) & mask) >>> 0);
  }

  /** Enumerate host addresses, capped to protect the UI. */
  function hostsOf(cidr, cap) {
    const info = cidrInfo(cidr);
    const limit = cap || 4096;
    const out = [];
    const start = info.prefix >= 31 ? info.networkInt : info.networkInt + 1;
    const end = info.prefix >= 31 ? info.broadcastInt : info.broadcastInt - 1;
    for (let n = start; n <= end && out.length < limit; n++) out.push(intToIp(n));
    return out;
  }

  /** Compress an IPv6 address string (display helper). */
  function compressIPv6(addr) {
    if (!addr || addr.indexOf('::') !== -1) return addr;
    const groups = addr.split(':').map((g) => g.replace(/^0+(?=.)/, ''));
    let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
    for (let i = 0; i < groups.length; i++) {
      if (groups[i] === '0') {
        if (curStart === -1) { curStart = i; curLen = 1; } else curLen++;
        if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
      } else { curStart = -1; curLen = 0; }
    }
    if (bestLen < 2) return groups.join(':');
    return groups.slice(0, bestStart).join(':') + '::' + groups.slice(bestStart + bestLen).join(':');
  }

  /** Basic hostname / FQDN validation for the authorized-target tools. */
  function isHostname(s) {
    const v = String(s).trim().toLowerCase();
    if (!v || v.length > 253) return false;
    if (isIPv4(v)) return false;
    return /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(v);
  }

  /**
   * Interpret a scope expression. Accepts a CIDR block, a single host, or a
   * comma-separated list. Returns a normalised, size-checked descriptor that
   * every active operation must be constrained by.
   */
  function parseScope(text) {
    const raw = String(text || '').trim();
    if (!raw) throw new Error('Scope is empty.');
    const parts = raw.split(/[,\s]+/).filter(Boolean);
    const entries = [];
    let totalHosts = 0;
    for (const p of parts) {
      if (p.indexOf('/') !== -1) {
        const info = cidrInfo(p);
        if (info.prefix < 16) throw new Error('Scope /' + info.prefix + ' is too broad. Use /16 or narrower.');
        entries.push({ kind: 'cidr', value: info.network + '/' + info.prefix, info });
        totalHosts += info.usableHosts;
      } else if (isIPv4(p)) {
        entries.push({ kind: 'host', value: p, info: cidrInfo(p + '/32') });
        totalHosts += 1;
      } else if (isHostname(p)) {
        entries.push({ kind: 'hostname', value: p.toLowerCase(), info: null });
        totalHosts += 1;
      } else {
        throw new Error('"' + p + '" is not a valid IPv4 address, CIDR block or hostname.');
      }
    }
    return {
      raw, entries, totalHosts,
      label: entries.map((e) => e.value).join(', '),
      contains(ip) {
        return entries.some((e) => {
          if (e.kind === 'hostname') return false;
          try { return ipInCidr(ip, e.value); } catch (err) { return false; }
        });
      }
    };
  }

  return {
    isIPv4, isHostname, ipToInt, intToIp, maskFromPrefix, prefixFromMask,
    parseCidr, cidrInfo, ipInCidr, hostsOf, isPrivate, isLoopback, isLinkLocal,
    compressIPv6, parseScope
  };
})();
