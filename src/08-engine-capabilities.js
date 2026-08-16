/* ============================================================================
   MODULE: CT.engines.capabilities
   ---------------------------------------------------------------------------
   Declares, honestly, what this runtime can and cannot do. The scan engine and
   every tool consult this before claiming a result. Nothing in the UI is
   allowed to present a simulated result as an observed one.
   ========================================================================= */
CT.engines = CT.engines || {};

CT.engines.capabilities = (function () {
  'use strict';

  const REAL = 'real', SIM = 'simulated', NA = 'unavailable';

  const CAPS = [
    { id: 'hostDiscovery', name: 'Host discovery (ICMP / ARP)', mode: NA,
      reason: 'Web runtimes cannot send ICMP or ARP frames. Host liveness cannot be observed from this platform.',
      fallback: 'Simulated against the selected demo environment.' },
    { id: 'portScan', name: 'TCP / UDP service probing', mode: NA,
      reason: 'Raw sockets are not available to web pages, so listening ports cannot be enumerated.',
      fallback: 'Simulated against the selected demo environment.' },
    { id: 'interfaceInfo', name: 'Local interface & Wi-Fi details', mode: NA,
      reason: 'Interface addresses, SSID and DHCP details are not exposed to web content by design.',
      fallback: 'Demo environment values, clearly labelled.' },
    { id: 'tlsHandshake', name: 'TLS handshake inspection', mode: NA,
      reason: 'The browser performs TLS itself and does not expose the peer certificate or negotiated cipher to scripts.',
      fallback: 'Offline certificate analysis from pasted PEM/DER is fully real — see Tools → TLS Inspector.' },
    { id: 'certParse', name: 'X.509 certificate parsing', mode: REAL,
      reason: 'Certificates supplied as PEM or DER are parsed locally by the built-in ASN.1 decoder.' },
    { id: 'headerAnalysis', name: 'HTTP security header analysis', mode: REAL,
      reason: 'Header and cookie evaluation runs locally against captured or pasted responses.' },
    { id: 'httpFetch', name: 'Live HTTP response fetch', mode: NA,
      reason: 'Cross-origin responses are hidden from scripts by the browser security model, so headers of a third-party host cannot be read.',
      fallback: 'Paste a raw response header block for a fully real analysis.' },
    { id: 'dns', name: 'DNS over HTTPS lookups', mode: REAL,
      reason: 'Standard DoH resolvers are queried directly. Requires outbound network access.' },
    { id: 'hashing', name: 'Local hash computation', mode: CT.crypto.available ? REAL : SIM,
      reason: CT.crypto.available
        ? 'SHA-1/256/384/512 via WebCrypto; MD5 via the bundled implementation. Input never leaves the device.'
        : 'WebCrypto requires a secure context (https:// or localhost). Only MD5 is available here.' },
    { id: 'cidr', name: 'IP / CIDR mathematics', mode: REAL,
      reason: 'Computed locally with exact integer arithmetic.' },
    { id: 'vault', name: 'Encrypted local storage', mode: CT.crypto.available ? REAL : NA,
      reason: CT.crypto.available
        ? 'AES-256-GCM with PBKDF2-SHA256 key derivation (210,000 iterations).'
        : 'WebCrypto is unavailable in this context, so at-rest encryption cannot be enabled.' },
    { id: 'notifications', name: 'System notifications', mode: ('Notification' in window) ? REAL : NA,
      reason: ('Notification' in window)
        ? 'Delivered through the platform notification service once permission is granted.'
        : 'The Notification API is not present in this runtime.' }
  ];

  const byId = {};
  CAPS.forEach((c) => { byId[c.id] = c; });

  function get(id) { return byId[id] || { id, name: id, mode: NA, reason: 'Unknown capability.' }; }
  function isReal(id) { return get(id).mode === REAL; }

  /** True when every capability an active scan needs is genuinely available. */
  function canRunLiveScan() {
    return isReal('hostDiscovery') && isReal('portScan');
  }

  function downloadSupported() {
    try {
      const a = document.createElement('a');
      return typeof a.download === 'string' && typeof URL.createObjectURL === 'function';
    } catch (e) { return false; }
  }

  return { CAPS, get, isReal, canRunLiveScan, downloadSupported, REAL, SIM, NA };
})();
