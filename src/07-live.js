/* ============================================================================
   MODULE: CT.live — client for the local scanner service
   ---------------------------------------------------------------------------
   Takes the slot the demo environment used to occupy. Every value that
   reaches the UI through here was measured by the service against a real
   network; nothing in this file invents anything.
   ========================================================================= */
CT.live = (function () {
  'use strict';

  let token = null;
  let cachedEnv = null;

  const state = { online: false, checked: false, info: null, error: null };

  /* The service prints a URL carrying the token. Take it once, remember it
     for the session, and strip it from the address bar so it is not shared
     by copying the URL out of the browser. */
  (function captureToken() {
    try {
      const url = new URL(location.href);
      const supplied = url.searchParams.get('t');
      if (supplied) {
        sessionStorage.setItem('ct.token', supplied);
        url.searchParams.delete('t');
        history.replaceState(null, '', url.pathname + url.search + url.hash);
      }
      token = sessionStorage.getItem('ct.token');
    } catch (e) { token = null; }
  })();

  function headers() {
    const h = { 'Content-Type': 'application/json' };
    if (token) h.Authorization = 'Bearer ' + token;
    return h;
  }

  async function call(path, body, timeoutMs) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs || 30000);
    try {
      const res = await fetch('api' + path, {
        method: body ? 'POST' : 'GET',
        headers: headers(),
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal
      });
      const text = await res.text();
      const data = text ? JSON.parse(text) : {};
      if (!res.ok) {
        const err = new Error(data.message || data.error || ('HTTP ' + res.status));
        err.code = data.error || String(res.status);
        throw err;
      }
      return data;
    } finally { clearTimeout(timer); }
  }

  /** Is the scanner service reachable? Everything else depends on this. */
  async function probe() {
    try {
      state.info = await call('/health', null, 4000);
      state.online = true;
      state.error = null;
    } catch (err) {
      state.online = false;
      state.info = null;
      state.error = err.code === 'unauthorized'
        ? 'The scanner service is running but rejected this session. Reopen the URL the service printed.'
        : 'No scanner service is reachable at this address.';
    }
    state.checked = true;
    return state.online;
  }

  /** The machine's real network configuration. */
  async function environment(force) {
    if (cachedEnv && !force) return cachedEnv;
    cachedEnv = await call('/interfaces', null, 8000);
    return cachedEnv;
  }

  function startScan(config) { return call('/scan', config, 15000); }
  function control(runId, action) { return call('/scan/' + runId + '/control', { action }); }
  function inspectTls(host, port, servername) {
    return call('/tls', { host, port: port || 443, servername }, 30000);
  }
  function fetchUrl(url) { return call('/http', { url }, 20000); }
  function checkPort(host, port) { return call('/port', { host, port }, 10000); }

  /**
   * Subscribe to a run's progress. EventSource cannot send an Authorization
   * header, so the token rides in the query string for this one request.
   */
  function stream(runId, handlers) {
    const suffix = token ? '?t=' + encodeURIComponent(token) : '';
    const source = new EventSource('api/scan/' + runId + '/events' + suffix);
    ['hello', 'progress', 'stage', 'log', 'state', 'host', 'done', 'failed'].forEach((type) => {
      source.addEventListener(type, (event) => {
        if (!handlers[type]) return;
        let payload = null;
        try { payload = JSON.parse(event.data); } catch (e) { return; }
        handlers[type](payload);
      });
    });
    source.addEventListener('done', () => source.close());
    source.addEventListener('failed', () => source.close());
    source.onerror = () => { if (handlers.disconnected) handlers.disconnected(); };
    return source;
  }

  /* ==========================================================================
     HYDRATION
     The service returns measurements. Naming a port, resolving an OUI and
     decoding a certificate all belong to reference data and parsers the
     client already holds, so they happen here rather than being duplicated
     server-side where they could drift.
     ======================================================================= */

  function hydrateService(service) {
    const ref = CT.data.portInfo(service.port);
    return Object.assign({}, service, {
      name: ref ? ref.name : (service.product || 'unknown'),
      service: ref ? ref.service : 'Unidentified service'
    });
  }

  function hydrateTls(tls) {
    if (!tls) return null;
    const out = Object.assign({}, tls);
    if (tls.certDer) {
      try { out.cert = CT.crypto.parseCertificate(tls.certDer); }
      catch (e) { out.cert = null; out.certParseError = e.message; }
    }
    delete out.certDer;
    return out;
  }

  /**
   * Turn service records into full CT assets.
   * @param {Array} assets    raw records from the service
   * @param {Array} [baseline] previous assessment's assets, for inInventory
   */
  function hydrate(assets, baseline) {
    const known = baseline ? new Set(baseline.map((a) => a.mac || a.ip)) : null;

    return assets.map((raw) => {
      const asset = Object.assign({}, raw);
      asset.services = (raw.services || []).map(hydrateService);
      asset.tls = hydrateTls(raw.tls);

      // A randomised MAC carries no manufacturer, so resolving it would
      // attribute the device to whoever owns that arbitrary prefix.
      asset.vendor = (raw.mac && !raw.macRandomised) ? CT.data.vendorForMac(raw.mac) : null;
      if (raw.macRandomised) asset.vendorNote = 'randomised MAC — no manufacturer can be derived';

      // Null until a baseline exists: on a first assessment there is nothing
      // for a device to be missing from.
      asset.inInventory = known ? known.has(raw.mac || raw.ip) : null;

      if (baseline) {
        const prior = baseline.find((a) => (a.mac && a.mac === raw.mac) || a.ip === raw.ip);
        if (prior) asset.firstSeen = prior.firstSeen;
      }
      return asset;
    });
  }

  return {
    get online() { return state.online; },
    get checked() { return state.checked; },
    get info() { return state.info; },
    get error() { return state.error; },
    get hasToken() { return !!token; },
    probe, environment, startScan, control, stream,
    inspectTls, fetchUrl, checkPort, hydrate
  };
})();

/* The screens that have not yet been rewritten still reference CT.demo.
   It resolves to the real environment with no pre-known assets, so nothing
   fabricated can reach the UI through it. */
CT.demo = {
  ENVIRONMENTS: [],
  build: function () {
    const env = CT.live.info && CT.live.cachedEnvironment ? CT.live.cachedEnvironment : null;
    return { network: env || { name: 'Local network', subnet: null, gateway: null }, assets: [] };
  }
};
