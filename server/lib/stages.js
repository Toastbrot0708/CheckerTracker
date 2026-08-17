/* ============================================================================
   The individual stages of a run. Each takes a context and reports what it
   observed; sequencing and progress live in assessment.js.
   ========================================================================= */
'use strict';

const { pool } = require('./pool');
const probe = require('./probe');
const tlsProbe = require('./tls-probe');
const httpProbe = require('./http-probe');
const names = require('./names');
const arp = require('./arp');
const identify = require('./identify');

/**
 * Which addresses are alive.
 *
 * 'passive' reads the kernel's ARP cache and sends nothing at all — the
 * profile is called Passive Discovery and against a real network that has
 * to mean what it says.
 */
async function discover(ctx) {
  if (ctx.depth === 'passive') {
    const table = await arp.table((ip) => ctx.scope.contains(ip));
    const found = Array.from(table.values()).map((entry) => ({
      ip: entry.ip, alive: true, evidence: 'arp-cache', openPorts: [], rttMs: null
    }));
    ctx.log('ARP cache: ' + found.length + ' known neighbours, no packets sent');
    return found;
  }

  const results = await pool(ctx.scope.addresses, ctx.concurrency, async (ip) => {
    const live = await probe.probeLiveness(ip, { timeoutMs: 700, control: ctx.control });
    ctx.tick();
    if (live.alive) {
      ctx.log('Host responding: ' + ip + ' (' + live.evidence + ')', 'hit');
      ctx.emit('host', { ip });
    }
    return live;
  }, ctx.control);

  return results.filter((r) => r && r.alive);
}

/** Full port sweep per live host. */
async function identifyServices(ctx, live) {
  if (ctx.depth !== 'services') {
    live.forEach(() => ctx.tick());
    return new Map();
  }

  const out = new Map();
  await pool(live, Math.max(4, Math.floor(ctx.concurrency / 8)), async (host) => {
    const scan = await probe.scanPorts(host.ip, ctx.ports, {
      timeoutMs: 900, concurrency: 24, control: ctx.control
    });
    out.set(host.ip, scan);
    ctx.tick();
    if (scan.open.length) {
      ctx.log(host.ip + ': ' + scan.open.length + ' open of ' + scan.tested +
        ' tested (' + scan.open.slice(0, 8).join(', ') + ')', 'hit');
    }
    return scan;
  }, ctx.control);

  return out;
}

/** Banners on the open ports, excluding the TLS ones. */
async function grabBanners(ctx, ip, openPorts) {
  const plain = openPorts.filter((p) => !probe.TLS_PORTS.has(p)).slice(0, 12);
  const banners = new Map();
  await pool(plain, 6, async (port) => {
    const text = await probe.grabBanner(ip, port, 1200);
    if (text) banners.set(port, text);
  }, ctx.control);
  return banners;
}

/** Names, TTL and classification. */
async function metadata(ctx, live, portMap, macTable) {
  const out = new Map();

  await pool(live, 12, async (host) => {
    const scan = portMap.get(host.ip);
    const openPorts = (scan && scan.open) || host.openPorts || [];

    const [name, ttl, banners] = await Promise.all([
      names.resolveHostname(host.ip, { timeoutMs: 1200 }),
      ctx.depth === 'passive' ? Promise.resolve(null) : identify.pingTtl(host.ip, 1000),
      ctx.depth === 'services' ? grabBanners(ctx, host.ip, openPorts) : Promise.resolve(new Map())
    ]);

    const macEntry = macTable.get(host.ip) || null;
    const classification = identify.classify({
      ip: host.ip,
      hostname: name ? name.name : null,
      ports: openPorts,
      banners: Array.from(banners.values()),
      ttl,
      isGateway: ctx.gateway === host.ip
    });

    out.set(host.ip, { name, ttl, banners, macEntry, classification });
    ctx.tick();
    if (name) ctx.log('Resolved ' + host.ip + ' -> ' + name.name + ' (' + name.source + ')');
    return null;
  }, ctx.control);

  return out;
}

/** Real handshakes against every open TLS port. */
async function inspectTls(ctx, targets) {
  const out = new Map();
  await pool(targets, 8, async (target) => {
    const result = await tlsProbe.inspect(target.ip, target.port, {
      servername: target.hostname, timeoutMs: 6000
    });
    ctx.tick();
    if (result.reachable) {
      out.set(target.ip, result);
      ctx.log('TLS ' + target.ip + ':' + target.port + '  ' +
        result.negotiated + '  ' + (result.cipher || 'cipher unknown') +
        (result.trusted ? '' : '  [' + (result.trustError || 'untrusted') + ']'));
    }
    return null;
  }, ctx.control);
  return out;
}

/** Real HTTP responses from every open web port. */
async function inspectHttp(ctx, targets) {
  const out = new Map();
  await pool(targets, 8, async (target) => {
    const result = await httpProbe.probeWeb(target.ip, target.port, {
      tls: target.tls, hostname: target.hostname, timeoutMs: 8000
    });
    ctx.tick();
    if (result) {
      out.set(target.ip, result);
      ctx.log('HTTP ' + target.ip + ':' + target.port + '  ' + result.status + '  ' +
        Object.keys(result.headers || {}).length + ' headers');
    }
    return null;
  }, ctx.control);
  return out;
}

/** Pick the endpoint to inspect per host: lowest open port of that kind. */
function pickTargets(live, portMap, meta, predicate) {
  const targets = [];
  live.forEach((host) => {
    const scan = portMap.get(host.ip);
    const open = (scan && scan.open) || host.openPorts || [];
    const match = open.filter(predicate).sort((a, b) => a - b)[0];
    if (match === undefined) return;
    const info = meta.get(host.ip);
    targets.push({
      ip: host.ip,
      port: match,
      hostname: info && info.name ? info.name.name : null,
      tls: probe.TLS_PORTS.has(match)
    });
  });
  return targets;
}

module.exports = {
  discover, identifyServices, metadata, inspectTls, inspectHttp, pickTargets, grabBanners
};
