/* ============================================================================
   MODULE: CT.engines.dns — DNS over HTTPS (genuine network lookups)
   Read-only resolution against public DoH resolvers. No zone transfer, no
   brute-force enumeration, no unsolicited traffic toward the queried host.
   ========================================================================= */
CT.engines.dns = (function () {
  'use strict';

  const TYPES = { A: 1, AAAA: 28, CNAME: 5, MX: 15, TXT: 16, NS: 2, SOA: 6, CAA: 257, SRV: 33, PTR: 12 };
  const TYPE_NAME = {};
  Object.keys(TYPES).forEach((k) => { TYPE_NAME[TYPES[k]] = k; });

  const RCODE = { 0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED' };

  const PROVIDERS = [
    { name: 'Cloudflare', url: (n, t) => 'https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(n) + '&type=' + t,
      headers: { accept: 'application/dns-json' } },
    { name: 'Google', url: (n, t) => 'https://dns.google/resolve?name=' + encodeURIComponent(n) + '&type=' + t,
      headers: { accept: 'application/json' } }
  ];

  async function queryOne(provider, name, type) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 7000);
    try {
      const res = await fetch(provider.url(name, type), { headers: provider.headers, signal: ctrl.signal, mode: 'cors' });
      if (!res.ok) throw new Error(provider.name + ' returned HTTP ' + res.status);
      return await res.json();
    } finally { clearTimeout(timer); }
  }

  /**
   * Resolve one record type. Tries each resolver in turn.
   * @returns {{provider, rcode, status, answers, authority, elapsedMs}}
   */
  async function resolve(name, typeName) {
    const type = TYPES[typeName];
    if (!type) throw new Error('Unsupported record type: ' + typeName);
    const host = String(name).trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (!CT.net.isHostname(host)) throw new Error('"' + host + '" is not a valid domain name.');

    const started = performance.now();
    const errors = [];
    for (const p of PROVIDERS) {
      try {
        const json = await queryOne(p, host, type);
        const answers = (json.Answer || []).map((a) => ({
          name: a.name, type: TYPE_NAME[a.type] || String(a.type), ttl: a.TTL, data: a.data
        }));
        const authority = (json.Authority || []).map((a) => ({
          name: a.name, type: TYPE_NAME[a.type] || String(a.type), ttl: a.TTL, data: a.data
        }));
        return {
          provider: p.name, rcode: json.Status, status: RCODE[json.Status] || ('RCODE ' + json.Status),
          answers, authority, question: host, recordType: typeName,
          elapsedMs: Math.round(performance.now() - started),
          truncated: !!json.TC, recursionDesired: !!json.RD, dnssecValidated: !!json.AD
        };
      } catch (e) {
        errors.push(p.name + ': ' + (e.name === 'AbortError' ? 'timed out after 7s' : e.message));
      }
    }
    const err = new Error('No DoH resolver could be reached. ' + errors.join(' · '));
    err.detail = errors;
    throw err;
  }

  /** Resolve several record types concurrently, keeping per-type errors. */
  async function resolveAll(name, typeNames) {
    const types = typeNames || ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS'];
    const results = await Promise.all(types.map((t) =>
      resolve(name, t).then((r) => ({ type: t, ok: true, result: r }))
                      .catch((e) => ({ type: t, ok: false, error: e.message }))));
    return results;
  }

  return { resolve, resolveAll, TYPES, RCODE };
})();
