/* ============================================================================
   Device type and OS inference.

   Everything here is an inference, never an observation, so every result
   carries the signals behind it and a confidence grade. A host that offers
   nothing distinctive stays Unknown — rounding it to the nearest plausible
   category would be inventing inventory.
   ========================================================================= */
'use strict';

const { execFile } = require('child_process');

/* Port sets that genuinely identify a class of device. Ordered: the first
   rule whose ports are present wins, so specific beats general. */
const FINGERPRINTS = [
  { type: 'Printer', ports: [9100], any: [515, 631], os: null,
    why: 'raw print port 9100 with a spooler service' },
  { type: 'Printer', ports: [631], any: [515], os: null, why: 'IPP and LPD print services' },
  { type: 'Camera', ports: [554], any: [80, 443, 8000], os: null, why: 'RTSP stream endpoint' },
  { type: 'NAS', ports: [445], any: [5000, 5001, 548, 2049, 873], os: null,
    why: 'SMB alongside NFS, AFP or a storage management interface' },
  { type: 'Smartphone', ports: [62078], any: [], os: 'iOS',
    why: 'iOS lockdown service on port 62078' },
  { type: 'Smartphone', ports: [5555], any: [], os: 'Android',
    why: 'Android debug bridge on port 5555' },
  { type: 'Router', ports: [53], any: [80, 443, 1900, 7547], os: null,
    why: 'DNS forwarder with a management interface' },
  { type: 'Switch', ports: [161], any: [22, 23], os: null,
    why: 'SNMP agent with a management shell' },
  { type: 'Server', ports: [3306], any: [], os: null, why: 'MySQL/MariaDB listener' },
  { type: 'Server', ports: [5432], any: [], os: null, why: 'PostgreSQL listener' },
  { type: 'Server', ports: [27017], any: [], os: null, why: 'MongoDB listener' },
  { type: 'Server', ports: [6379], any: [], os: null, why: 'Redis listener' },
  { type: 'Server', ports: [389], any: [88, 445], os: 'Windows Server',
    why: 'LDAP with Kerberos or SMB — a directory role' },
  { type: 'IoT', ports: [1883], any: [], os: null, why: 'MQTT broker' },
  { type: 'IoT', ports: [8123], any: [], os: null, why: 'Home Assistant interface' },
  { type: 'Desktop', ports: [3389], any: [445, 139], os: 'Windows',
    why: 'RDP with SMB — a Windows workstation or server' },
  { type: 'Server', ports: [22], any: [80, 443, 8080], os: null,
    why: 'SSH alongside a web service' }
];

/* Hostname conventions worth reading, but only as a weak signal. */
const NAME_HINTS = [
  { re: /(printer|drucker|mfp|officejet|laserjet|brother|epson|kyocera)/i, type: 'Printer' },
  { re: /(iphone|ipad|android|galaxy|pixel|oneplus)/i, type: 'Smartphone' },
  { re: /(macbook|thinkpad|laptop|notebook|xps)/i, type: 'Laptop' },
  { re: /(nas|synology|qnap|diskstation|truenas|unraid)/i, type: 'NAS' },
  { re: /(router|fritz|gateway|openwrt|unifi|edgerouter|speedport)/i, type: 'Router' },
  { re: /(switch|sg\d|catalyst)/i, type: 'Switch' },
  { re: /(cam|kamera|doorbell|ring|nest)/i, type: 'Camera' },
  { re: /(esp|shelly|tasmota|sonoff|tuya|hue|echo|alexa|chromecast|firetv)/i, type: 'IoT' },
  { re: /(srv|server|host\d|vm\d|docker|proxmox)/i, type: 'Server' },
  { re: /(tv|bravia|samsung|lg-)/i, type: 'IoT' }
];

/* Banner text that states an operating system outright. */
const OS_BANNERS = [
  { re: /ubuntu/i, os: 'Linux (Ubuntu)' },
  { re: /debian/i, os: 'Linux (Debian)' },
  { re: /raspbian/i, os: 'Linux (Raspberry Pi OS)' },
  { re: /centos|red hat|rhel/i, os: 'Linux (RHEL family)' },
  { re: /alpine/i, os: 'Linux (Alpine)' },
  { re: /freebsd/i, os: 'FreeBSD' },
  { re: /microsoft|win32|windows/i, os: 'Windows' },
  { re: /synology|dsm/i, os: 'Synology DSM' },
  { re: /openwrt/i, os: 'OpenWrt' },
  { re: /mikrotik|routeros/i, os: 'MikroTik RouterOS' }
];

/** ICMP echo via the system ping binary. Returns the reply TTL, or null. */
function pingTtl(ip, timeoutMs) {
  const args = process.platform === 'win32'
    ? ['-n', '1', '-w', String(timeoutMs || 1000), ip]
    : process.platform === 'darwin'
      ? ['-c', '1', '-t', '1', ip]
      : ['-c', '1', '-W', '1', ip];

  return new Promise((resolve) => {
    execFile('ping', args, { timeout: (timeoutMs || 1000) + 1500, windowsHide: true }, (err, stdout) => {
      const text = String(stdout || '');
      const m = text.match(/ttl[=\s:]*(\d+)/i);
      resolve(m ? Number(m[1]) : null);
    });
  });
}

/**
 * Initial TTL inferred from the observed one. Hops only ever decrement it,
 * so the value rounds up to the nearest standard starting point.
 */
function osFromTtl(ttl) {
  if (!ttl) return null;
  if (ttl > 128) return { os: 'Network device or BSD', why: 'IP TTL near 255' };
  if (ttl > 64) return { os: 'Windows', why: 'IP TTL near 128' };
  if (ttl > 32) return { os: 'Linux, macOS, Android or iOS', why: 'IP TTL near 64' };
  return null;
}

/**
 * Classify one host.
 *
 * @param {object} host { ip, hostname, ports:number[], banners:string[],
 *                        ttl, isGateway, vendor }
 */
function classify(host) {
  const ports = host.ports || [];
  const has = (p) => ports.indexOf(p) !== -1;
  const signals = [];
  let type = null;
  let os = null;

  if (host.isGateway) {
    type = 'Router';
    signals.push('carries the default route for this segment');
  }

  if (!type) {
    for (const fp of FINGERPRINTS) {
      const core = fp.ports.every(has);
      const extra = !fp.any.length || fp.any.some(has);
      if (core && extra) {
        type = fp.type;
        if (fp.os) os = fp.os;
        signals.push(fp.why);
        break;
      }
    }
  }

  const name = host.hostname || '';
  const nameHint = NAME_HINTS.find((h) => h.re.test(name));
  if (nameHint) {
    signals.push('hostname "' + name + '" matches a ' + nameHint.type.toLowerCase() + ' naming convention');
    if (!type) type = nameHint.type;
  }

  const bannerText = (host.banners || []).join('\n');
  const osBanner = OS_BANNERS.find((b) => b.re.test(bannerText));
  if (osBanner) {
    os = osBanner.os;
    signals.push('service banner names ' + osBanner.os);
  }

  if (!os) {
    const ttlGuess = osFromTtl(host.ttl);
    if (ttlGuess) { os = ttlGuess.os; signals.push(ttlGuess.why); }
  }

  if (!type && host.vendor) {
    signals.push('MAC vendor ' + host.vendor);
  }

  // Two independent signals is a real classification. One is a lead.
  const confidence = signals.length >= 2 ? 'high' : signals.length === 1 ? 'medium' : null;

  return {
    deviceType: type || 'Unknown',
    os: os || null,
    osConfidence: os ? (osBanner ? 'high' : 'low') : null,
    typeConfidence: type ? confidence : null,
    signals
  };
}

module.exports = { classify, pingTtl, osFromTtl, FINGERPRINTS };
