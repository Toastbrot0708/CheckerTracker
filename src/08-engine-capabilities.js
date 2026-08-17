/* ============================================================================
   MODULE: CT.engines.capabilities
   ---------------------------------------------------------------------------
   Declares what this installation can actually do. Every engine and tool
   consults it before claiming a result.

   Five capabilities depend on the local scanner service. They are computed
   from whether it answers, never asserted, so the matrix cannot drift away
   from real behaviour.
   ========================================================================= */
CT.engines = CT.engines || {};

CT.engines.capabilities = (function () {
  'use strict';

  const REAL = 'real', SIM = 'simulated', NA = 'unavailable';

  const NO_SERVICE = 'The local scanner service is not reachable from this page. ' +
    'Start it with "node server/checkertracker.js" on a machine in the network you are assessing.';

  let CAPS = [];

  function build() {
    const live = CT.live && CT.live.online;

    CAPS = [
      { id: 'hostDiscovery', name: 'Host discovery', mode: live ? REAL : NA,
        reason: live
          ? 'TCP reachability sweep performed by the scanner service. An accepted or refused connection both prove a host is present.'
          : NO_SERVICE,
        fallback: live ? null : 'No discovery is performed at all.' },

      { id: 'portScan', name: 'TCP service probing', mode: live ? REAL : NA,
        reason: live
          ? 'Full TCP connect scan across the reference port set, with banner collection on the ports that answer.'
          : NO_SERVICE },

      { id: 'interfaceInfo', name: 'Local interface & Wi-Fi details', mode: live ? REAL : NA,
        reason: live
          ? 'Read from the operating system: interfaces, default gateway, resolvers and SSID. DHCP details have no portable source and are reported as not determined.'
          : 'Interface addresses, SSID and DHCP details are not exposed to web content by design. ' + NO_SERVICE },

      { id: 'tlsHandshake', name: 'TLS handshake inspection', mode: live ? REAL : NA,
        reason: live
          ? 'Real handshakes against the target, including per-version negotiation tests. The certificate is decoded on this device.'
          : 'The browser performs TLS itself and does not expose the peer certificate to scripts. ' + NO_SERVICE,
        fallback: live ? null : 'Offline certificate analysis from pasted PEM or DER is fully real — see Tools → TLS Inspector.' },

      { id: 'httpFetch', name: 'Live HTTP response fetch', mode: live ? REAL : NA,
        reason: live
          ? 'Requests are made by the scanner service, so the complete response head is visible rather than the handful of fields a browser exposes cross-origin.'
          : 'Cross-origin responses are hidden from scripts by the browser security model. ' + NO_SERVICE,
        fallback: live ? null : 'Paste a raw response header block for a fully real analysis.' },

      { id: 'macAddress', name: 'MAC address and vendor', mode: live ? REAL : NA,
        reason: live
          ? 'Read from the kernel ARP cache after the sweep. Locally administered addresses are flagged and not resolved to a manufacturer.'
          : NO_SERVICE },

      { id: 'hostnameResolution', name: 'Hostname resolution', mode: live ? REAL : NA,
        reason: live
          ? 'Reverse DNS, multicast DNS and NetBIOS node status, whichever answers first. Each name records its source.'
          : NO_SERVICE },

      { id: 'certParse', name: 'X.509 certificate parsing', mode: REAL,
        reason: 'Certificates supplied as PEM or DER are decoded locally by the built-in ASN.1 parser.' },

      { id: 'headerAnalysis', name: 'HTTP security header analysis', mode: REAL,
        reason: 'Header and cookie evaluation runs locally against captured or pasted responses.' },

      { id: 'dns', name: 'DNS over HTTPS lookups', mode: REAL,
        reason: 'Standard DoH resolvers are queried directly. Requires outbound network access.' },

      { id: 'hashing', name: 'Local hash computation', mode: CT.crypto.available ? REAL : SIM,
        reason: CT.crypto.available
          ? 'SHA-1/256/384/512 via WebCrypto; MD5 via the bundled implementation. Input never leaves the device.'
          : 'WebCrypto requires a secure context. Over plain HTTP only MD5 is available — start the service with --tls to restore the rest.' },

      { id: 'cidr', name: 'IP / CIDR mathematics', mode: REAL,
        reason: 'Computed locally with exact integer arithmetic.' },

      { id: 'vault', name: 'Encrypted local storage', mode: CT.crypto.available ? REAL : NA,
        reason: CT.crypto.available
          ? 'AES-256-GCM with PBKDF2-SHA256 key derivation (210,000 iterations).'
          : 'WebCrypto is unavailable outside a secure context, so at-rest encryption cannot be enabled. Start the service with --tls, or open the app on localhost.' },

      { id: 'notifications', name: 'System notifications', mode: ('Notification' in window) ? REAL : NA,
        reason: ('Notification' in window)
          ? 'Delivered through the platform notification service once permission is granted.'
          : 'The Notification API is not present in this runtime.' }
    ];

    return CAPS;
  }

  build();

  function get(id) {
    const found = CAPS.find((c) => c.id === id);
    return found || { id, name: id, mode: NA, reason: 'Unknown capability.' };
  }

  function isReal(id) { return get(id).mode === REAL; }

  /** True when every capability an active scan needs is genuinely available. */
  function canRunLiveScan() { return isReal('hostDiscovery') && isReal('portScan'); }

  function downloadSupported() {
    try {
      const a = document.createElement('a');
      return typeof a.download === 'string' && typeof URL.createObjectURL === 'function';
    } catch (e) { return false; }
  }

  return {
    get CAPS() { return CAPS; },
    refresh: build,
    get, isReal, canRunLiveScan, downloadSupported,
    REAL, SIM, NA
  };
})();
