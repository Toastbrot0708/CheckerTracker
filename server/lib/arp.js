/* ============================================================================
   MAC addresses from the kernel's ARP cache.

   Ordering matters: an ARP entry exists only after the kernel has exchanged
   frames with that host, so this must run *after* the TCP sweep. Reading it
   first returns a nearly empty table.

   ARP is link-local. A host behind a router has the router's MAC, not its
   own, so entries that do not sit inside one of this machine's own subnets
   are discarded instead of being attributed to the wrong device.
   ========================================================================= */
'use strict';

const fs = require('fs');
const { execFile } = require('child_process');

const MAC_RE = /^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$/i;

function normaliseMac(raw) {
  if (!raw) return null;
  const text = String(raw).trim().toLowerCase();
  if (!MAC_RE.test(text)) return null;
  const mac = text.replace(/-/g, ':');
  return mac === '00:00:00:00:00:00' || mac === 'ff:ff:ff:ff:ff:ff' ? null : mac;
}

/**
 * The second-least-significant bit of the first octet marks a locally
 * administered address. Phones randomise their MAC per network, so the OUI
 * means nothing and must not be resolved to a vendor.
 */
function isLocallyAdministered(mac) {
  if (!mac) return false;
  return (parseInt(mac.slice(0, 2), 16) & 0x02) === 0x02;
}

function readProcArp() {
  let text;
  try { text = fs.readFileSync('/proc/net/arp', 'utf8'); }
  catch (e) { return null; }

  const out = [];
  text.split('\n').slice(1).forEach((line) => {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 6) return;
    const [ip, , flags, hw, , device] = cols;
    // flags 0x0 means the entry is incomplete: no reply was ever received.
    if (flags === '0x0') return;
    const mac = normaliseMac(hw);
    if (mac) out.push({ ip, mac, iface: device || null });
  });
  return out;
}

function runArp() {
  return new Promise((resolve) => {
    const args = process.platform === 'win32' ? ['-a'] : ['-an'];
    execFile('arp', args, { timeout: 5000, windowsHide: true }, (err, stdout) => {
      if (err) { resolve([]); return; }
      resolve(parseArpOutput(String(stdout)));
    });
  });
}

function parseArpOutput(text) {
  const out = [];
  text.split('\n').forEach((line) => {
    // BSD/macOS:  ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
    // Windows:      192.168.1.1        aa-bb-cc-dd-ee-ff     dynamic
    const ip = line.match(/(\d{1,3}(?:\.\d{1,3}){3})/);
    const hw = line.match(/([0-9a-f]{2}(?:[:-][0-9a-f]{2}){5})/i);
    if (!ip || !hw) return;
    const mac = normaliseMac(hw[1]);
    const iface = line.match(/\son\s+(\S+)/);
    if (mac) out.push({ ip: ip[1], mac, iface: iface ? iface[1] : null });
  });
  return out;
}

/**
 * Current ARP cache as an ip -> record map.
 * @param {(ip:string)=>boolean} [isLocal] drops entries outside our own subnets
 */
async function table(isLocal) {
  const entries = readProcArp() || await runArp();
  const map = new Map();

  entries.forEach((entry) => {
    if (isLocal && !isLocal(entry.ip)) return;
    if (map.has(entry.ip)) return;
    map.set(entry.ip, {
      ip: entry.ip,
      mac: entry.mac,
      iface: entry.iface,
      randomised: isLocallyAdministered(entry.mac)
    });
  });

  return map;
}

module.exports = { table, normaliseMac, isLocallyAdministered, parseArpOutput };
