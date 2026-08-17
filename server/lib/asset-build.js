/* ============================================================================
   Turning probe results into an asset record.

   Shape matches CT's Asset model exactly, with two deliberate gaps:
   `vendor` is left for the client, which holds the OUI table, and `tls.cert`
   arrives as DER for the client's ASN.1 decoder rather than being parsed
   twice by two different parsers.
   ========================================================================= */
'use strict';

const probe = require('./probe');

/* Port -> protocol label. Only what a port number alone actually tells you. */
const UDP_PORTS = new Set([53, 67, 68, 123, 137, 138, 161, 500, 1900, 5353]);

function serviceRecord(port, banner) {
  const ident = probe.identifyBanner(banner);
  return {
    port,
    proto: UDP_PORTS.has(port) ? 'udp' : 'tcp',
    // `name` and `service` are filled by the client from CT.data.portInfo,
    // which is the single reference table. Nothing is guessed here.
    name: null,
    service: null,
    product: ident.product,
    version: ident.version,
    versionConfidence: ident.confidence,
    banner: banner || null
  };
}

/**
 * Build one asset from everything observed about an address.
 *
 * @param {object} o {
 *   ip, liveness, portScan, banners:Map, tls, http, name, macEntry, ttl,
 *   isGateway, observedAt
 * }
 */
function buildAsset(o) {
  const openPorts = (o.portScan && o.portScan.open) || o.liveness.openPorts || [];
  const banners = o.banners || new Map();

  const services = openPorts
    .slice()
    .sort((a, b) => a - b)
    .map((port) => serviceRecord(port, banners.get(port)));

  const hostname = o.name ? o.name.name : null;
  const classification = o.classification || {
    deviceType: 'Unknown', os: null, osConfidence: null, typeConfidence: null, signals: []
  };

  return {
    id: 'asset-' + o.ip.replace(/\./g, '-'),
    ip: o.ip,
    hostname,
    hostnameSource: o.name ? o.name.source : null,
    ipv6: null,                       // no IPv6 sweep in this release
    mac: o.macEntry ? o.macEntry.mac : null,
    macRandomised: o.macEntry ? o.macEntry.randomised : false,
    vendor: null,                     // resolved client-side from the OUI table
    deviceType: classification.deviceType,
    deviceTypeConfidence: classification.typeConfidence,
    os: classification.os,
    osConfidence: classification.osConfidence,
    inferenceSignals: classification.signals,

    // Operator metadata. There is no source for these until somebody sets
    // them, so they stay empty instead of being defaulted to something
    // that would read as fact in a report.
    owner: null,
    criticality: 'standard',
    inInventory: null,                // set by the client against the baseline
    tags: [],

    status: 'reachable',
    reachedBy: o.liveness.evidence,   // 'tcp-open' or 'tcp-refused'
    rttMs: o.liveness.rttMs,
    ttl: o.ttl || null,
    firstSeen: o.observedAt,
    lastSeen: o.observedAt,

    services,
    tls: o.tls || null,
    http: o.http || null,

    // Exactly what this scan covered, so nothing downstream can overstate it.
    coverage: o.portScan ? {
      portsTested: o.portScan.tested,
      portsOpen: openPorts.length,
      portsClosed: o.portScan.closed,
      portsFiltered: o.portScan.filtered,
      method: 'tcp-connect'
    } : {
      portsTested: probe.LIVENESS_PORTS.length,
      portsOpen: openPorts.length,
      portsClosed: null,
      portsFiltered: null,
      method: 'tcp-connect (liveness only)'
    }
  };
}

/** Shape a tls-probe result for the asset's `tls` field. */
function tlsRecord(result) {
  if (!result || !result.reachable) return null;
  return {
    port: result.port,
    protocols: result.protocols,
    protocolsRefused: result.protocolsRefused,
    protocolsUntestable: result.protocolsUntestable,
    negotiated: result.negotiated,
    minProtocol: result.minProtocol,
    cipher: result.cipher,
    alpn: result.alpn,
    trusted: result.trusted,
    trustError: result.trustError,
    chainLength: result.chainLength,
    certDer: result.certDer,        // parsed by CT.crypto on the client
    cert: null
  };
}

module.exports = { buildAsset, serviceRecord, tlsRecord };
