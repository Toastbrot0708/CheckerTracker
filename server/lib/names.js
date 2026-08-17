/* ============================================================================
   Hostname resolution from three real sources.

   Home networks rarely have PTR records, so reverse DNS alone leaves an
   inventory full of bare addresses. mDNS covers Apple, Android and most IoT;
   NetBIOS covers Windows and NAS boxes. Each answer records where it came
   from, so no name is ever unattributable.

   All three are read-only lookups. No zone transfer, no name enumeration.
   ========================================================================= */
'use strict';

const dgram = require('dgram');
const dns = require('dns').promises;

/* -- DNS wire format ------------------------------------------------------ */

function encodeName(name) {
  const parts = String(name).split('.').filter(Boolean);
  const bufs = parts.map((label) => {
    const bytes = Buffer.from(label, 'ascii');
    return Buffer.concat([Buffer.from([bytes.length]), bytes]);
  });
  return Buffer.concat(bufs.concat([Buffer.from([0])]));
}

/** Read a possibly compressed name. Returns [name, offsetAfterName]. */
function readName(buf, offset) {
  const labels = [];
  let pos = offset;
  let after = null;
  let hops = 0;

  while (pos < buf.length) {
    const len = buf[pos];
    if (len === 0) { pos += 1; break; }
    if ((len & 0xC0) === 0xC0) {
      if (pos + 1 >= buf.length) break;
      if (after === null) after = pos + 2;
      pos = ((len & 0x3F) << 8) | buf[pos + 1];
      if (++hops > 16) break;            // malformed packet, refuse to loop
      continue;
    }
    if (pos + 1 + len > buf.length) break;
    labels.push(buf.toString('ascii', pos + 1, pos + 1 + len));
    pos += 1 + len;
  }
  return [labels.join('.'), after === null ? pos : after];
}

function queryPacket(id, name, type, klass) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x0000, 2);      // standard query, recursion not desired
  header.writeUInt16BE(1, 4);           // one question
  const tail = Buffer.alloc(4);
  tail.writeUInt16BE(type, 0);
  tail.writeUInt16BE(klass, 2);
  return Buffer.concat([header, encodeName(name), tail]);
}

function sendUdp(packet, host, port, timeoutMs, bindMulticast) {
  return new Promise((resolve) => {
    const socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      try { socket.close(); } catch (e) { /* already closed */ }
      resolve(value);
    };

    const timer = setTimeout(() => finish(null), timeoutMs);
    socket.once('error', () => { clearTimeout(timer); finish(null); });
    socket.once('message', (msg) => { clearTimeout(timer); finish(msg); });

    socket.bind(0, () => {
      try { if (bindMulticast) socket.setMulticastTTL(1); } catch (e) { /* not fatal */ }
      socket.send(packet, 0, packet.length, port, host, (err) => { if (err) finish(null); });
    });
  });
}

/* -- Reverse DNS ---------------------------------------------------------- */

async function reverseDns(ip, timeoutMs) {
  try {
    const names = await Promise.race([
      dns.reverse(ip),
      new Promise((resolve) => setTimeout(() => resolve(null), timeoutMs || 2000))
    ]);
    if (names && names.length) return { name: names[0], source: 'reverse-dns' };
  } catch (e) { /* NXDOMAIN is the normal case on a home LAN */ }
  return null;
}

/* -- mDNS ----------------------------------------------------------------- */

/**
 * Reverse PTR over multicast DNS.
 * Class 0x8001 sets the unicast-response bit, so the answer comes back to
 * this socket directly rather than to the multicast group.
 */
async function mdnsName(ip, timeoutMs) {
  const arpa = ip.split('.').reverse().join('.') + '.in-addr.arpa';
  const packet = queryPacket(0, arpa, 12 /* PTR */, 0x8001);
  const reply = await sendUdp(packet, '224.0.0.251', 5353, timeoutMs || 1200, true);
  if (!reply || reply.length < 12) return null;

  const answers = reply.readUInt16BE(6);
  if (!answers) return null;

  let pos = 12;
  const questions = reply.readUInt16BE(4);
  for (let i = 0; i < questions; i++) {
    pos = readName(reply, pos)[1] + 4;
  }

  for (let i = 0; i < answers && pos + 10 < reply.length; i++) {
    pos = readName(reply, pos)[1];
    const type = reply.readUInt16BE(pos);
    const rdlen = reply.readUInt16BE(pos + 8);
    const rdata = pos + 10;
    if (type === 12) {
      const name = readName(reply, rdata)[0];
      if (name) return { name: name.replace(/\.$/, ''), source: 'mdns' };
    }
    pos = rdata + rdlen;
  }
  return null;
}

/* -- NetBIOS -------------------------------------------------------------- */

/** First-level encoding: each byte becomes two nibble characters from 'A'. */
function encodeNetbiosName(name) {
  const padded = Buffer.alloc(16, 0x20);
  Buffer.from(name, 'ascii').copy(padded, 0, 0, Math.min(15, name.length));
  padded[15] = 0x00;
  const out = Buffer.alloc(34);
  out[0] = 0x20;
  for (let i = 0; i < 16; i++) {
    out[1 + i * 2] = 0x41 + ((padded[i] >> 4) & 0x0F);
    out[2 + i * 2] = 0x41 + (padded[i] & 0x0F);
  }
  out[33] = 0x00;
  return out;
}

/** NBSTAT node status request — asks a host to list its own NetBIOS names. */
async function netbiosName(ip, timeoutMs) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(0x4354, 0);      // transaction id
  const tail = Buffer.alloc(4);
  tail.writeUInt16BE(0x0021, 0);        // NBSTAT
  tail.writeUInt16BE(0x0001, 2);        // IN
  header.writeUInt16BE(1, 4);

  const packet = Buffer.concat([header, encodeNetbiosName('*'), tail]);
  const reply = await sendUdp(packet, ip, 137, timeoutMs || 1200, false);
  if (!reply || reply.length < 57) return null;

  // header(12) + echoed question(34 + 4) + type/class/ttl/rdlength(10)
  let pos = 12 + 34 + 4 + 10;
  if (pos >= reply.length) return null;
  const count = reply[pos];
  pos += 1;

  let workstation = null;
  let group = null;
  for (let i = 0; i < count && pos + 18 <= reply.length; i++) {
    const label = reply.toString('ascii', pos, pos + 15).trim();
    const suffix = reply[pos + 15];
    const flags = reply.readUInt16BE(pos + 16);
    const isGroup = (flags & 0x8000) !== 0;
    if (!isGroup && suffix === 0x00 && !workstation) workstation = label;
    if (isGroup && suffix === 0x00 && !group) group = label;
    pos += 18;
  }

  if (!workstation) return null;
  return { name: workstation, workgroup: group, source: 'netbios' };
}

/* -- Combined ------------------------------------------------------------- */

/**
 * Best available name for one address.
 * Reverse DNS is the most authoritative when it exists; mDNS and NetBIOS
 * fill the gap it usually leaves on a private network.
 */
async function resolveHostname(ip, options) {
  const opts = options || {};
  const timeout = opts.timeoutMs || 1200;
  return (await reverseDns(ip, timeout)) ||
         (await mdnsName(ip, timeout)) ||
         (await netbiosName(ip, timeout)) ||
         null;
}

module.exports = { resolveHostname, reverseDns, mdnsName, netbiosName, readName, encodeName };
