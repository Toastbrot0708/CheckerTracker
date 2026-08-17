/* ============================================================================
   The machine's real network configuration.

   Where a value cannot be read on this platform it is reported as null. The
   UI renders that as "not determined". Filling the gap with something
   plausible is the exact behaviour this service exists to eliminate.

   Subprocesses use execFile with fixed argument arrays and no shell, so no
   operator input can reach a command line.
   ========================================================================= */
'use strict';

const os = require('os');
const dns = require('dns');
const { execFile } = require('child_process');
const { ipToInt, intToIp, cidrInfo, safeRangeOf } = require('./scope');

function run(command, args, timeoutMs) {
  return new Promise((resolve) => {
    execFile(command, args, { timeout: timeoutMs || 4000, windowsHide: true },
      (err, stdout) => resolve(err ? null : String(stdout)));
  });
}

/** Prefix length from a dotted netmask. */
function prefixFromNetmask(netmask) {
  try {
    let bits = ipToInt(netmask);
    let count = 0;
    while (bits & 0x80000000) { count++; bits = (bits << 1) >>> 0; }
    return count;
  } catch (e) { return null; }
}

/** Every non-loopback IPv4 interface this machine actually has. */
function interfaces() {
  const raw = os.networkInterfaces();
  const out = [];

  Object.keys(raw).forEach((name) => {
    (raw[name] || []).forEach((entry) => {
      if (entry.family !== 'IPv4' && entry.family !== 4) return;
      if (entry.internal) return;

      const prefix = entry.cidr
        ? Number(String(entry.cidr).split('/')[1])
        : prefixFromNetmask(entry.netmask);
      let info = null;
      try { info = prefix != null ? cidrInfo(entry.address + '/' + prefix) : null; }
      catch (e) { info = null; }

      out.push({
        name,
        address: entry.address,
        netmask: entry.netmask,
        prefix,
        mac: entry.mac && entry.mac !== '00:00:00:00:00:00' ? entry.mac : null,
        subnet: info ? info.network + '/' + info.prefix : null,
        hostRange: info ? info.firstHost + ' – ' + info.lastHost : null,
        usableHosts: info ? info.usableHosts : null,
        addressSpace: safeRangeOf(entry.address) || 'public / other',
        ipv6: ipv6For(raw[name])
      });
    });
  });

  return out;
}

function ipv6For(entries) {
  const found = (entries || []).find((e) =>
    (e.family === 'IPv6' || e.family === 6) && !e.internal && !String(e.address).startsWith('fe80'));
  return found ? found.address : null;
}

/** Default gateway, read from the routing table. */
async function defaultGateway() {
  if (process.platform === 'linux') {
    const out = await run('ip', ['-4', 'route', 'show', 'default']);
    const m = out && out.match(/default\s+via\s+([\d.]+)(?:\s+dev\s+(\S+))?/);
    if (m) return { address: m[1], iface: m[2] || null };
  }
  if (process.platform === 'darwin') {
    const out = await run('route', ['-n', 'get', 'default']);
    const gw = out && out.match(/gateway:\s*([\d.]+)/);
    const dev = out && out.match(/interface:\s*(\S+)/);
    if (gw) return { address: gw[1], iface: dev ? dev[1] : null };
  }
  if (process.platform === 'win32') {
    const out = await run('route', ['print', '-4']);
    const m = out && out.match(/\s0\.0\.0\.0\s+0\.0\.0\.0\s+([\d.]+)/);
    if (m) return { address: m[1], iface: null };
  }
  // Last resort that observes rather than guesses: netstat is present nearly
  // everywhere and prints the same table.
  const out = await run('netstat', ['-rn']);
  const m = out && out.match(/(?:^|\n)(?:default|0\.0\.0\.0)\s+([\d.]+)/);
  return m ? { address: m[1], iface: null } : null;
}

/** Resolvers the OS is configured to use. */
function resolvers() {
  try { return dns.getServers(); } catch (e) { return []; }
}

/** Wi-Fi SSID, when the platform will say and the link is wireless. */
async function wifi() {
  if (process.platform === 'linux') {
    const iw = await run('iwgetid', ['-r']);
    if (iw && iw.trim()) return { ssid: iw.trim(), source: 'iwgetid' };
    const nm = await run('nmcli', ['-t', '-f', 'active,ssid', 'dev', 'wifi']);
    const line = nm && nm.split('\n').find((l) => l.indexOf('yes:') === 0);
    if (line) return { ssid: line.slice(4).trim(), source: 'nmcli' };
    return null;
  }
  if (process.platform === 'darwin') {
    for (const port of ['en0', 'en1']) {
      const out = await run('networksetup', ['-getairportnetwork', port]);
      const m = out && out.match(/Current Wi-Fi Network:\s*(.+)/);
      if (m) return { ssid: m[1].trim(), source: 'networksetup ' + port };
    }
    return null;
  }
  if (process.platform === 'win32') {
    const out = await run('netsh', ['wlan', 'show', 'interfaces']);
    const ssid = out && out.match(/^\s*SSID\s*:\s*(.+)$/m);
    const signal = out && out.match(/^\s*Signal\s*:\s*(.+)$/m);
    if (ssid) {
      return { ssid: ssid[1].trim(), signal: signal ? signal[1].trim() : null, source: 'netsh' };
    }
  }
  return null;
}

/**
 * Everything the Discover screen needs, all of it observed.
 * The primary interface is the one carrying the default route.
 */
async function environment() {
  const list = interfaces();
  const gateway = await defaultGateway();
  const link = await wifi();

  let primary = null;
  if (gateway) {
    primary = list.find((i) => i.name === gateway.iface) ||
      list.find((i) => sameSubnet(i, gateway.address)) || null;
  }
  if (!primary) primary = list[0] || null;

  return {
    hostname: os.hostname(),
    platform: process.platform,
    interfaces: list,
    primary,
    gateway: gateway ? gateway.address : null,
    dnsServers: resolvers(),
    wifi: link,
    // No portable way to read these without a DHCP client library or root.
    // Reported as absent rather than approximated.
    dhcpServer: null,
    dhcpLease: null,
    observedAt: Date.now()
  };
}

function sameSubnet(iface, address) {
  if (!iface || !iface.prefix) return false;
  try {
    const info = cidrInfo(iface.address + '/' + iface.prefix);
    const value = ipToInt(address);
    return value >= ipToInt(info.network) && value <= ipToInt(info.broadcast);
  } catch (e) { return false; }
}

module.exports = { interfaces, defaultGateway, resolvers, wifi, environment, intToIp };
