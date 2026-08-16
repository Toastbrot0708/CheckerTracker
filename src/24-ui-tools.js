/* ============================================================================
   MODULE: CT.ui.routes.tools — the utility belt
   Most of these are genuinely real: CIDR mathematics, DNS over HTTPS, X.509
   parsing, header analysis, the port reference and hashing all run for real.
   Each tool states its own capability honestly at the top of the screen.
   ========================================================================= */
(function () {
  'use strict';
  const h = CT.dom.h, icon = CT.dom.icon, S = CT.ui.shell;

  const TOOLS = [
    { id: 'cidr', name: 'IP / CIDR Calculator', icon: 'grid', cap: 'cidr',
      desc: 'Network, broadcast, host range and host count for any IPv4 block.' },
    { id: 'dns', name: 'DNS Inspector', icon: 'globe', cap: 'dns',
      desc: 'A, AAAA, CNAME, MX, TXT and NS records for authorized domains.' },
    { id: 'tls', name: 'TLS Inspector', icon: 'certificate', cap: 'certParse',
      desc: 'Parse and evaluate an X.509 certificate entirely on device.' },
    { id: 'headers', name: 'HTTP Header Analyzer', icon: 'layers', cap: 'headerAnalysis',
      desc: 'CSP, HSTS, nosniff, Referrer-Policy, Permissions-Policy and cookie flags.' },
    { id: 'ports', name: 'Port / Service Reference', icon: 'book', cap: 'cidr',
      desc: 'What a port is, whether it is encrypted, and why it matters.' },
    { id: 'hash', name: 'Hash Utility', icon: 'hash', cap: 'hashing',
      desc: 'SHA-256, SHA-1 and MD5 over text or a local file.' },
    { id: 'notes', name: 'Notes', icon: 'note', cap: 'cidr',
      desc: 'Technical notes attached to the current assessment.' }
  ];

  CT.ui.routes.tools = {
    parent: '#/more', tab: 'more',
    title: () => 'Tools',
    subtitle: () => 'Utilities for authorized work',
    render() {
      return h('div.stack.gap12', [
        h('div.card.flush', h('div.list', TOOLS.map((t) => {
          const cap = CT.engines.capabilities.get(t.cap);
          return h('button.list-item', { type: 'button', onClick: () => S.navigate('#/tool/' + t.id) }, [
            h('span', { style: { color: 'var(--accent)', display: 'flex' } }, icon(t.icon)),
            h('span.grow.stack', [
              h('span.row.gap6', [
                h('span', { style: { 'font-size': '0.9em', 'font-weight': '600' } }, t.name),
                cap.mode === 'real' ? h('span.pill.ok', 'Real') : h('span.pill.medium', 'Limited')
              ]),
              h('span.tiny.muted', t.desc)
            ]),
            icon('chevronRight', { cls: 'chev' })
          ]);
        }))),
        h('div.notice', [icon('shield'), h('div.grow', [
          h('strong', 'Authorized use only'),
          h('span', 'The DNS Inspector reaches out to public resolvers. Use it only for domains you own or are explicitly permitted to assess. Every other tool runs entirely on this device.')
        ])])
      ]);
    }
  };

  CT.ui.routes.tool = {
    parent: '#/tools', tab: 'more',
    title: (p) => { const t = TOOLS.find((x) => x.id === p[0]); return t ? t.name : 'Tool'; },
    render(params) {
      const t = TOOLS.find((x) => x.id === params[0]);
      if (!t) return CT.dom.empty({ icon: 'tools', title: 'Unknown tool', body: 'That tool does not exist.',
        action: { label: 'Back to Tools', onClick: () => S.navigate('#/tools') } });
      return h('div.stack.gap12', [S.capabilityNote(t.cap), RENDER[t.id]()]);
    }
  };

  /* ==========================================================================
     CIDR CALCULATOR
     ======================================================================= */
  let cidrValue = '192.168.1.0/24';

  function cidrTool() {
    const out = h('div');
    const input = h('input', {
      type: 'text', value: cidrValue, spellcheck: 'false', autocapitalize: 'off',
      'aria-label': 'CIDR block', placeholder: '192.168.1.0/24',
      on: { input: CT.util.debounce(function () { cidrValue = this.value; compute(); }, 150) }
    });

    function compute() {
      CT.dom.clear(out);
      if (!cidrValue.trim()) { out.appendChild(h('p.small.muted', 'Enter an address or CIDR block.')); return; }
      let info;
      try { info = CT.net.cidrInfo(cidrValue); }
      catch (e) { out.appendChild(CT.dom.notice('err', 'Invalid input', e.message)); return; }

      out.appendChild(h('div.card', [
        h('div.card-head', [icon('grid'), h('h3', info.input)]),
        h('dl', [
          CT.dom.kv('Network', info.network, { mono: true }),
          CT.dom.kv('Broadcast', info.broadcast, { mono: true }),
          CT.dom.kv('Host range', info.rangeLabel, { mono: true }),
          CT.dom.kv('Usable hosts', CT.util.fmtNum(info.usableHosts), { mono: true }),
          CT.dom.kv('Total addresses', CT.util.fmtNum(info.totalAddresses), { mono: true }),
          CT.dom.kv('Netmask', info.netmask, { mono: true }),
          CT.dom.kv('Wildcard mask', info.wildcard, { mono: true }),
          CT.dom.kv('Prefix', '/' + info.prefix, { mono: true }),
          CT.dom.kv('Class', info.class),
          CT.dom.kv('Address space', info.isPrivate ? 'RFC 1918 private' : 'Public / other')
        ]),
        h('button.btn.sm.ghost.mt12', {
          type: 'button',
          onClick: () => CT.util.copyText(
            ['Network:   ' + info.network, 'Broadcast: ' + info.broadcast,
             'Range:     ' + info.rangeLabel, 'Hosts:     ' + info.usableHosts,
             'Netmask:   ' + info.netmask, 'Wildcard:  ' + info.wildcard].join('\n')
          ).then((ok) => S.toast(ok ? 'Copied' : 'Clipboard unavailable', ok ? 'ok' : 'warn'))
        }, [icon('copy'), 'Copy result'])
      ]));

      const cur = CT.store.currentAssessment();
      if (cur && cur.assets.length) {
        const inRange = cur.assets.filter((a) => { try { return CT.net.ipInCidr(a.ip, info.network + '/' + info.prefix); } catch (e) { return false; } });
        out.appendChild(h('div.card', [
          h('div.card-head', [icon('server'), h('h3', 'Known assets in this block')]),
          inRange.length
            ? h('div.list', inRange.slice(0, 25).map((a) => h('button.list-item', {
              type: 'button', onClick: () => S.navigate('#/asset/' + a.id)
            }, [
              h('span.mono.small', { style: { flex: '0 0 108px' } }, a.ip),
              h('span.grow.trunc.small', a.hostname || a.deviceType),
              icon('chevronRight', { cls: 'chev' })
            ])))
            : h('p.small.muted', 'No asset from the current assessment falls inside this block.')
        ]));
      }

      out.appendChild(h('div.card', [
        h('div.card-head', [icon('layers'), h('h3', 'Common prefixes')]),
        h('div.tbl-wrap', h('table.tbl', [
          h('thead', h('tr', [h('th', 'Prefix'), h('th', 'Netmask'), h('th', 'Hosts')])),
          h('tbody', [30, 29, 28, 27, 26, 25, 24, 23, 22, 20, 16].map((p) => {
            const i2 = CT.net.cidrInfo(info.network + '/' + p);
            return h('tr.clickable', { onClick: () => { cidrValue = info.network + '/' + p; input.value = cidrValue; compute(); } }, [
              h('td', h('span.mono', '/' + p)),
              h('td', h('span.mono.tiny', i2.netmask)),
              h('td.num', CT.util.fmtNum(i2.usableHosts))
            ]);
          }))
        ]))
      ]));
    }

    compute();
    return h('div.stack.gap12', [
      h('div.card', [
        h('label.field', { style: { margin: 0 } }, [
          h('span.lbl', 'IPv4 address or CIDR block'),
          input,
          h('span.hint', 'Accepts 10.0.0.0/8, 192.168.1.20 (treated as /32), 172.16.4.0/22 …')
        ])
      ]),
      out
    ]);
  }

  /* ==========================================================================
     DNS INSPECTOR
     ======================================================================= */
  let dnsDomain = 'example.com';
  let dnsTypes = { A: true, AAAA: true, CNAME: true, MX: true, TXT: true, NS: true };

  function dnsTool() {
    const out = h('div');
    const runBtn = h('button.btn.primary.block', { type: 'button', onClick: run }, [icon('search'), 'Resolve records']);

    async function run() {
      const types = Object.keys(dnsTypes).filter((k) => dnsTypes[k]);
      if (!types.length) { S.toast('Select at least one record type', 'warn'); return; }
      if (!CT.net.isHostname(dnsDomain.trim())) {
        CT.dom.mount(out, CT.dom.notice('err', 'Invalid domain', '"' + dnsDomain + '" is not a valid domain name.'));
        return;
      }
      runBtn.disabled = true;
      runBtn.textContent = 'Resolving…';
      CT.dom.mount(out, h('div.card', h('p.small.muted', 'Querying DNS over HTTPS…')));
      try {
        const results = await CT.engines.dns.resolveAll(dnsDomain.trim(), types);
        CT.store.audit('tool.run', 'DNS Inspector resolved ' + dnsDomain.trim() + ' (' + types.join(', ') + ')');
        CT.store.commit();
        renderResults(results);
      } catch (e) {
        CT.dom.mount(out, CT.dom.notice('err', 'Lookup failed', e.message));
      } finally {
        runBtn.disabled = false;
        CT.dom.mount(runBtn, [icon('search'), 'Resolve records']);
      }
    }

    function renderResults(results) {
      const anyOk = results.some((r) => r.ok);
      CT.dom.mount(out, h('div.stack.gap12', [
        !anyOk ? CT.dom.notice('err', 'No resolver could be reached',
          'Every DoH request failed. This usually means the runtime has no outbound network access, or a content policy blocks the resolver host. The analysis engine itself is working — only the network call failed.') : null,
        h('div.stack.gap12', results.map((r) => {
          if (!r.ok) {
            return h('div.card.tight', [
              h('div.row.gap8', [h('span.tag', r.type), h('span.tiny.muted.grow', 'query failed'),
                h('span.status-dot.critical', { 'aria-hidden': 'true' })]),
              h('p.tiny.muted.mt6', { style: { margin: '6px 0 0' } }, r.error)
            ]);
          }
          const res = r.result;
          return h('div.card', [
            h('div.card-head', [
              h('span.tag', r.type), h('h3', { style: { 'font-size': '0.86em' } }, res.question),
              h('span.pill.' + (res.rcode === 0 ? 'ok' : 'medium'), res.status)
            ]),
            res.answers.length
              ? h('div.tbl-wrap', h('table.tbl', [
                h('thead', h('tr', [h('th', 'Type'), h('th', 'TTL'), h('th', 'Data')])),
                h('tbody', res.answers.map((a) => h('tr', [
                  h('td', h('span.tag', a.type)),
                  h('td.num', String(a.ttl)),
                  h('td', h('span.mono.tiny', { style: { 'word-break': 'break-all' } }, a.data))
                ])))
              ]))
              : h('p.small.muted', res.rcode === 3 ? 'NXDOMAIN — the name does not exist.' : 'No records of this type.'),
            h('div.row.gap8.mt8', [
              h('span.tiny.muted', res.provider),
              h('span.tiny.muted', res.elapsedMs + ' ms'),
              res.dnssecValidated ? h('span.pill.ok', 'DNSSEC') : null
            ])
          ]);
        }))
      ]));
    }

    return h('div.stack.gap12', [
      h('div.card', [
        h('label.field', [
          h('span.lbl', 'Domain'),
          h('input', {
            type: 'text', value: dnsDomain, spellcheck: 'false', autocapitalize: 'off',
            'aria-label': 'Domain name', placeholder: 'example.com',
            on: { input: function () { dnsDomain = this.value; } }
          }),
          h('span.hint', 'Only query domains you own or are explicitly authorized to assess.')
        ]),
        h('div.section-label', 'Record types'),
        h('div.chips', Object.keys(dnsTypes).map((t) => h('button.chip', {
          type: 'button', 'aria-pressed': dnsTypes[t] ? 'true' : 'false',
          onClick: function () { dnsTypes[t] = !dnsTypes[t]; this.setAttribute('aria-pressed', dnsTypes[t] ? 'true' : 'false'); }
        }, t))),
        h('div.mt12', runBtn)
      ]),
      out
    ]);
  }

  /* ==========================================================================
     TLS INSPECTOR
     ======================================================================= */
  let pemText = '';
  let tlsHostname = '';

  function tlsTool() {
    const out = h('div');
    const ta = h('textarea', {
      placeholder: '-----BEGIN CERTIFICATE-----\nMIID…\n-----END CERTIFICATE-----',
      spellcheck: 'false', 'aria-label': 'Certificate in PEM format',
      style: { 'font-family': 'var(--mono)', 'font-size': '0.74em' },
      on: { input: function () { pemText = this.value; } }
    }, pemText);

    function analyse() {
      let cert;
      try { cert = CT.crypto.parseCertificate(pemText); }
      catch (e) {
        CT.dom.mount(out, CT.dom.notice('err', 'Could not parse certificate',
          e.message + ' Paste the full PEM block including the BEGIN and END lines, or raw base64 DER.'));
        return;
      }
      const host = tlsHostname.trim() || null;
      const issues = CT.engines.tls.evaluate({ protocols: [], cert }, host);
      CT.store.audit('tool.run', 'TLS Inspector parsed a certificate for ' + (cert.subjectCN || 'unknown subject'));
      CT.store.commit();
      CT.dom.mount(out, certificateView(cert, issues, host));
    }

    return h('div.stack.gap12', [
      h('div.card', [
        h('label.field', [h('span.lbl', 'Certificate (PEM or base64 DER)'), ta,
          h('span.hint', 'Parsed locally by the built-in ASN.1 decoder. Nothing is uploaded.')]),
        h('label.field', [
          h('span.lbl', 'Hostname to validate against (optional)'),
          h('input', { type: 'text', value: tlsHostname, spellcheck: 'false', autocapitalize: 'off',
            placeholder: 'www.example.com', 'aria-label': 'Hostname',
            on: { input: function () { tlsHostname = this.value; } } }),
          h('span.hint', 'Checks CN and SAN entries with RFC 6125 wildcard rules.')
        ]),
        h('button.btn.primary.block', { type: 'button', onClick: analyse }, [icon('certificate'), 'Analyse certificate'])
      ]),
      h('div.card', [
        h('div.card-head', [icon('database'), h('h3', 'Evaluate a demo certificate')]),
        h('p.small.dim.mb12', 'Runs the same evaluator against certificate metadata from the demo environment. The evaluation is real; the certificate fields are simulated.'),
        h('div.stack.gap8', demoCerts().map((d) => h('button.btn.sm.ghost', {
          type: 'button',
          onClick: () => {
            const issues = CT.engines.tls.evaluate(d.asset.tls, (d.asset.hostname || '').toLowerCase() + '.corp-lab.internal');
            CT.dom.mount(out, h('div.stack.gap12', [
              h('div.demo-banner', [icon('alert'), h('div.grow', [h('strong', 'DEMO DATA'),
                ' — certificate fields come from the simulated environment; the evaluation below is the production evaluator.'])]),
              certificateView(Object.assign({}, d.asset.tls.cert, { validityDays: null, extensions: [] }), issues,
                (d.asset.hostname || '').toLowerCase() + '.corp-lab.internal', d.asset.tls)
            ]));
          }
        }, d.asset.hostname + ' — ' + d.label)))
      ]),
      out
    ]);
  }

  function demoCerts() {
    const env = CT.demo.build('corp-lab');
    return env.assets.filter((a) => a.tls && a.tls.cert).map((a) => {
      const days = Math.floor((a.tls.cert.notAfter - Date.now()) / 86400000);
      return { asset: a, label: days < 0 ? 'expired ' + Math.abs(days) + 'd ago' : 'expires in ' + days + 'd' };
    });
  }

  function certificateView(cert, issues, host, tls) {
    const days = Math.floor((cert.notAfter - Date.now()) / 86400000);
    const state = cert.expired || days < 0 ? { kind: 'critical', label: 'Expired' }
      : days < 30 ? { kind: 'medium', label: 'Expires soon' }
        : { kind: 'ok', label: 'Valid' };
    return h('div.stack.gap12', [
      h('div.card', [
        h('div.row.gap8.wrap.mb8', [
          h('span.pill.' + state.kind, state.label),
          cert.selfSigned ? h('span.pill.medium', 'Self-signed') : h('span.tag', 'CA issued'),
          h('span.tag', cert.sigAlg),
          cert.keyBits ? h('span.tag', (cert.keyAlg || '') + ' ' + cert.keyBits + '-bit') : null
        ]),
        h('dl', [
          CT.dom.kv('Subject CN', cert.subjectCN || '—', { mono: true }),
          CT.dom.kv('Issuer CN', cert.issuerCN || '—'),
          cert.issuerO ? CT.dom.kv('Issuer org', cert.issuerO) : null,
          CT.dom.kv('Valid from', CT.util.fmtDateTime(cert.notBefore)),
          CT.dom.kv('Valid until', CT.util.fmtDateTime(cert.notAfter)),
          CT.dom.kv('Days remaining', days < 0 ? 'expired ' + Math.abs(days) + ' days ago' : String(days)),
          cert.serial ? CT.dom.kv('Serial', cert.serial, { mono: true }) : null,
          cert.version ? CT.dom.kv('Version', 'v' + cert.version) : null,
          CT.dom.kv('Signature algorithm', cert.sigAlg, { mono: true }),
          CT.dom.kv('Public key', (cert.keyAlg || '?') + (cert.keyBits ? ' ' + cert.keyBits + '-bit' : '') + (cert.curve ? ' (' + cert.curve + ')' : ''), { mono: true }),
          tls && tls.protocols ? CT.dom.kv('Protocols', tls.protocols.join(', '), { mono: true }) : null,
          tls && tls.cipher ? CT.dom.kv('Cipher', tls.cipher, { mono: true }) : null
        ])
      ]),
      (cert.san && cert.san.length) ? h('div.card', [
        h('div.card-head', [icon('list'), h('h3', 'Subject Alternative Names')]),
        h('div.row.wrap.gap6', cert.san.map((n) => h('span.tag', n))),
        host ? h('div.mt12', h('div.row.gap8', [
          h('span.status-dot.' + (CT.crypto.hostnameMatches(host, cert.san) ? 'ok' : 'critical'), { 'aria-hidden': 'true' }),
          h('span.small', CT.crypto.hostnameMatches(host, cert.san)
            ? '"' + host + '" matches this certificate'
            : '"' + host + '" does NOT match any name in this certificate')
        ])) : null
      ]) : null,
      (cert.keyUsage && cert.keyUsage.length) || (cert.extKeyUsage && cert.extKeyUsage.length) ? h('div.card', [
        h('div.card-head', [icon('key'), h('h3', 'Key usage')]),
        cert.keyUsage && cert.keyUsage.length ? h('div', [h('div.tiny.muted.mb6', 'Key usage'),
          h('div.row.wrap.gap6', cert.keyUsage.map((k) => h('span.tag', k)))]) : null,
        cert.extKeyUsage && cert.extKeyUsage.length ? h('div.mt8', [h('div.tiny.muted.mb6', 'Extended key usage'),
          h('div.row.wrap.gap6', cert.extKeyUsage.map((k) => h('span.tag', k)))]) : null,
        cert.basicConstraints ? h('div.mt8', h('span.tag', cert.basicConstraints.ca ? 'CA:TRUE' : 'CA:FALSE')) : null
      ]) : null,
      (cert.extensions && cert.extensions.length) ? h('div.card', [
        h('div.card-head', [icon('layers'), h('h3', 'Extensions')]),
        h('div.tbl-wrap', h('table.tbl', [
          h('thead', h('tr', [h('th', 'Extension'), h('th', 'OID'), h('th', 'Critical')])),
          h('tbody', cert.extensions.map((e) => h('tr', [
            h('td', e.name), h('td', h('span.mono.tiny', e.oid)),
            h('td', e.critical ? h('span.pill.medium', 'yes') : h('span.tiny.muted', 'no'))
          ])))
        ]))
      ]) : null,
      h('div.card', [
        h('div.card-head', [icon('shieldCheck'), h('h3', 'Evaluation')]),
        issues.length
          ? h('div.list', issues.map((i) => {
            const rule = CT.data.rule(i.ruleId);
            return h('div.list-item.static', { style: { display: 'block' } }, [
              h('div.row.gap6', [S.severityPill(i.severity || rule.severity, { short: true }), h('span.tag', i.ruleId)]),
              h('div.small.mt4', { style: { 'font-weight': '600' } }, rule.title),
              h('div.tiny.muted.mt4', i.detail)
            ]);
          }))
          : h('div.row.gap8', [h('span.status-dot.ok', { 'aria-hidden': 'true' }),
            h('span.small.dim', 'No certificate issues detected by the evaluator.')])
      ])
    ]);
  }

  /* ==========================================================================
     HTTP HEADER ANALYZER
     ======================================================================= */
  let headerMode = 'paste';
  let headerRaw = 'HTTP/1.1 200 OK\nServer: nginx/1.18.0 (Ubuntu)\nContent-Type: text/html; charset=UTF-8\nX-Powered-By: PHP/8.1.2\nX-Frame-Options: SAMEORIGIN\nSet-Cookie: PHPSESSID=REDACTED; Path=/\nStrict-Transport-Security: max-age=86400';
  let headerUrl = 'https://example.com';
  let headerScheme = 'https';

  function headersTool() {
    const out = h('div');

    function analysePaste() {
      let parsed;
      try { parsed = CT.engines.web.parseRawHeaders(headerRaw); }
      catch (e) { CT.dom.mount(out, CT.dom.notice('err', 'Could not parse response', e.message)); return; }
      parsed.scheme = headerScheme;
      CT.store.audit('tool.run', 'HTTP Header Analyzer evaluated a pasted response');
      CT.store.commit();
      CT.dom.mount(out, headerResultView(parsed, 'Pasted response head'));
    }

    async function analyseUrl() {
      CT.dom.mount(out, h('div.card', h('p.small.muted', 'Requesting ' + headerUrl + ' …')));
      let url;
      try { url = new URL(headerUrl); }
      catch (e) { CT.dom.mount(out, CT.dom.notice('err', 'Invalid URL', 'Enter a full URL including the scheme, for example https://example.com')); return; }
      try {
        const res = await fetch(url.href, { method: 'GET', redirect: 'follow' });
        const headers = {};
        res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
        const readable = Object.keys(headers).length;
        const parsed = {
          status: res.status, scheme: url.protocol.replace(':', ''), headers,
          cookies: [], redirect: headers['location'] || null, server: headers['server'] || null
        };
        CT.dom.mount(out, h('div.stack.gap12', [
          CT.dom.notice(readable > 3 ? 'ok' : 'warn',
            readable > 3 ? 'Response received' : 'Response received, but headers are hidden',
            readable > 3
              ? 'The server returned ' + readable + ' readable headers.'
              : 'The request succeeded (' + res.status + ') but the browser only exposes CORS-safelisted headers for cross-origin responses, so security headers cannot be read this way. Use paste mode with the output of "curl -sSI ' + url.href + '" for a complete analysis.'),
          headerResultView(parsed, 'Live fetch of ' + url.host)
        ]));
      } catch (e) {
        CT.dom.mount(out, CT.dom.notice('err', 'Request blocked',
          'The browser refused the cross-origin request (' + e.message + '). This is the browser security model, not a property of the target. Switch to paste mode and supply the response head from curl or your proxy for a complete, real analysis.'));
      }
    }

    return h('div.stack.gap12', [
      h('div.card', [
        h('div.segmented.mb12', { role: 'group', 'aria-label': 'Input mode' }, [
          h('button', { type: 'button', 'aria-pressed': headerMode === 'paste' ? 'true' : 'false',
            onClick: () => { headerMode = 'paste'; S.render(); } }, 'Paste response'),
          h('button', { type: 'button', 'aria-pressed': headerMode === 'url' ? 'true' : 'false',
            onClick: () => { headerMode = 'url'; S.render(); } }, 'Fetch URL')
        ]),
        headerMode === 'paste'
          ? h('div', [
            h('label.field', [
              h('span.lbl', 'Raw response head'),
              h('textarea', {
                spellcheck: 'false', 'aria-label': 'Raw HTTP response headers',
                style: { 'font-family': 'var(--mono)', 'font-size': '0.74em', 'min-height': '150px' },
                on: { input: function () { headerRaw = this.value; } }
              }, headerRaw),
              h('span.hint', 'Paste the output of curl -sSI https://host/ — status line plus headers.')
            ]),
            h('label.field', [
              h('span.lbl', 'Scheme'),
              h('select', { 'aria-label': 'Scheme', on: { change: function () { headerScheme = this.value; } } }, [
                h('option', { value: 'https', selected: headerScheme === 'https' ? true : null }, 'https'),
                h('option', { value: 'http', selected: headerScheme === 'http' ? true : null }, 'http')
              ]),
              h('span.hint', 'HSTS is only evaluated for HTTPS responses.')
            ]),
            h('button.btn.primary.block', { type: 'button', onClick: analysePaste }, [icon('layers'), 'Analyse headers'])
          ])
          : h('div', [
            h('label.field', [
              h('span.lbl', 'URL'),
              h('input', { type: 'text', value: headerUrl, spellcheck: 'false', autocapitalize: 'off',
                'aria-label': 'URL', on: { input: function () { headerUrl = this.value; } } }),
              h('span.hint', 'Only request systems you are authorized to assess. Cross-origin header visibility is restricted by the browser.')
            ]),
            h('button.btn.primary.block', { type: 'button', onClick: analyseUrl }, [icon('globe'), 'Fetch and analyse'])
          ])
      ]),
      out
    ]);
  }

  function headerResultView(parsed, sourceLabel) {
    const rows = CT.engines.web.headerReport(parsed);
    const issues = CT.engines.web.evaluate(parsed);
    const missing = rows.filter((r) => r.state === 'missing').length;
    const grade = missing === 0 ? { k: 'ok', l: 'All core headers present' }
      : missing <= 2 ? { k: 'medium', l: missing + ' core headers missing' }
        : { k: 'high', l: missing + ' core headers missing' };

    return h('div.stack.gap12', [
      h('div.card', [
        h('div.row.gap8.wrap.mb8', [
          h('span.pill.' + grade.k, grade.l),
          parsed.status ? h('span.tag', 'HTTP ' + parsed.status) : null,
          h('span.tag', parsed.scheme)
        ]),
        h('p.tiny.muted', sourceLabel),
        h('div.tbl-wrap.mt8', h('table.tbl', [
          h('thead', h('tr', [h('th', 'Header'), h('th', 'State'), h('th', 'Value')])),
          h('tbody', rows.map((r) => h('tr', [
            h('td', r.label),
            h('td', h('span.pill.' + (r.state === 'ok' ? 'ok' : r.state === 'missing' ? 'medium' : r.state === 'weak' ? 'medium' : 'info'),
              r.state === 'ok' ? 'Set' : r.state === 'missing' ? 'Missing' : r.state === 'weak' ? 'Weak' : r.state === 'na' ? 'N/A' : 'Info')),
            h('td', h('span.tiny.mono', { style: { 'word-break': 'break-all' } }, r.note))
          ])))
        ]))
      ]),
      (parsed.cookies || []).length ? h('div.card', [
        h('div.card-head', [icon('key'), h('h3', 'Cookies')]),
        h('p.tiny.muted.mb8', { style: { margin: '0 0 8px' } }, 'Attribute analysis only. Cookie values are never stored or transmitted by this app.'),
        h('div.tbl-wrap', h('table.tbl', [
          h('thead', h('tr', [h('th', 'Name'), h('th', 'Secure'), h('th', 'HttpOnly'), h('th', 'SameSite')])),
          h('tbody', parsed.cookies.map((c) => h('tr', [
            h('td', h('span.mono.tiny', c.name)),
            h('td', flag(c.secure)), h('td', flag(c.httpOnly)),
            h('td', c.sameSite ? h('span.tiny', c.sameSite) : flag(false))
          ])))
        ]))
      ]) : null,
      h('div.card', [
        h('div.card-head', [icon('alert'), h('h3', 'Findings (' + issues.length + ')')]),
        issues.length
          ? h('div.list', issues.map((i) => {
            const rule = CT.data.rule(i.ruleId);
            return h('div.list-item.static', { style: { display: 'block' } }, [
              h('div.row.gap6', [S.severityPill(i.severity || rule.severity, { short: true }), h('span.tag', i.ruleId)]),
              h('div.small.mt4', { style: { 'font-weight': '600' } }, rule.title),
              h('div.tiny.muted.mt4', i.detail),
              h('div.tiny.mt6', { style: { color: 'var(--text-2)' } }, (rule.remediation || [])[0] || '')
            ]);
          }))
          : h('div.row.gap8', [h('span.status-dot.ok', { 'aria-hidden': 'true' }), h('span.small.dim', 'No header issues detected.')])
      ])
    ]);
  }
  function flag(v) {
    return h('span.row.gap4', [h('span.status-dot.' + (v ? 'ok' : 'medium'), { 'aria-hidden': 'true' }), h('span.tiny', v ? 'yes' : 'no')]);
  }

  /* ==========================================================================
     PORT REFERENCE
     ======================================================================= */
  let portQuery = '';

  function portsTool() {
    const listBox = h('div.card.flush');
    function refresh() {
      const q = portQuery.trim().toLowerCase();
      const items = CT.data.PORTS.filter((p) => !q ||
        String(p.port).indexOf(q) === 0 ||
        p.name.toLowerCase().indexOf(q) !== -1 ||
        p.service.toLowerCase().indexOf(q) !== -1 ||
        p.category.toLowerCase().indexOf(q) !== -1);
      CT.dom.clear(listBox);
      if (!items.length) {
        listBox.appendChild(CT.dom.empty({ icon: 'book', title: 'No match', body: 'No reference entry matches "' + portQuery + '".' }));
        return;
      }
      listBox.appendChild(h('div.list', items.map((p) => h('button.list-item', {
        type: 'button',
        onClick: () => S.sheet({
          title: p.port + '/' + p.proto + ' · ' + p.name,
          body: h('div.stack.gap12', [
            h('dl', [
              CT.dom.kv('Port', p.port + '/' + p.proto, { mono: true }),
              CT.dom.kv('Common name', p.name),
              CT.dom.kv('Service', p.service),
              CT.dom.kv('Category', p.category),
              CT.dom.kv('Transport encryption', p.encrypted ? 'Yes' : 'No'),
              CT.dom.kv('Administrative', p.admin ? 'Yes' : 'No')
            ]),
            CT.dom.notice(p.admin ? 'warn' : null, 'Reference note', p.note)
          ])
        })
      }, [
        h('span.mono', { style: { flex: '0 0 76px', 'font-weight': '650', 'font-size': '0.85em' } }, p.port + '/' + p.proto),
        h('span.grow.stack', { style: { 'min-width': '0' } }, [
          h('span.small.trunc', p.name),
          h('span.tiny.muted.trunc', p.service)
        ]),
        p.admin ? h('span.pill.medium', 'admin') : null,
        p.encrypted ? h('span.status-dot.ok', { 'aria-hidden': 'true', title: 'Encrypted' })
          : h('span.status-dot.medium', { 'aria-hidden': 'true', title: 'Cleartext' })
      ]))));
    }
    refresh();
    return h('div.stack.gap10', [
      h('div.search-bar', [
        icon('search'),
        h('input', {
          type: 'search', placeholder: 'Port number, service or category', 'aria-label': 'Search port reference',
          on: { input: CT.util.debounce(function () { portQuery = this.value; refresh(); }, 120) }
        })
      ]),
      h('div.row.gap8', [
        h('span.tiny.muted.grow', CT.data.PORTS.length + ' reference entries'),
        h('span.row.gap4', [h('span.status-dot.ok', { 'aria-hidden': 'true' }), h('span.tiny.muted', 'encrypted')]),
        h('span.row.gap4', [h('span.status-dot.medium', { 'aria-hidden': 'true' }), h('span.tiny.muted', 'cleartext')])
      ]),
      listBox
    ]);
  }

  /* ==========================================================================
     HASH UTILITY
     ======================================================================= */
  let hashText = '';

  function hashTool() {
    const out = h('div');

    async function computeText() {
      if (!hashText) { CT.dom.mount(out, h('div.card', h('p.small.muted', 'Enter some text to hash.'))); return; }
      await computeFrom(new TextEncoder().encode(hashText), 'Text input · ' + hashText.length + ' characters');
    }

    async function computeFrom(bytes, label) {
      CT.dom.mount(out, h('div.card', h('p.small.muted', 'Computing…')));
      const results = [];
      for (const algo of ['SHA-256', 'SHA-1', 'MD5']) {
        try { results.push({ algo, value: await CT.crypto.digest(algo, bytes) }); }
        catch (e) { results.push({ algo, error: e.message }); }
      }
      CT.store.audit('tool.run', 'Hash Utility computed digests (' + label + ')');
      CT.store.commit();
      CT.dom.mount(out, h('div.stack.gap12', [
        h('div.card', [
          h('div.card-head', [icon('hash'), h('h3', 'Digests')]),
          h('p.tiny.muted.mb8', { style: { margin: '0 0 8px' } }, label + ' · ' + CT.util.fmtBytes(bytes.length)),
          h('div.stack.gap10', results.map((r) => h('div', [
            h('div.row.gap8.mb4', [
              h('span.tag', r.algo),
              r.algo === 'MD5' || r.algo === 'SHA-1' ? h('span.pill.medium', 'legacy') : h('span.pill.ok', 'current'),
              h('span.grow'),
              !r.error ? h('button.btn.sm.quiet', {
                type: 'button',
                onClick: () => CT.util.copyText(r.value).then((ok) => S.toast(ok ? 'Copied' : 'Clipboard unavailable', ok ? 'ok' : 'warn'))
              }, icon('copy')) : null
            ]),
            r.error ? h('p.tiny', { style: { color: 'var(--sev-critical)' } }, r.error)
              : h('pre.code.wrap-lines', r.value)
          ])))
        ]),
        CT.dom.notice('warn', 'Hashes are one-way',
          'A hash cannot be reversed and does not "decrypt" a password. CheckerTracker provides hashing to verify file and configuration integrity. It contains no lookup, cracking or recovery capability, and MD5 and SHA-1 are included only for compatibility with legacy checksums — neither is suitable for security purposes.')
      ]));
    }

    return h('div.stack.gap12', [
      h('div.card', [
        h('label.field', [
          h('span.lbl', 'Text'),
          h('textarea', {
            placeholder: 'Paste text, a configuration snippet or a checksum source…',
            spellcheck: 'false', 'aria-label': 'Text to hash',
            on: { input: function () { hashText = this.value; } }
          }, hashText),
          h('span.hint', 'Never paste passwords, private keys or tokens. This tool has no need for them and CheckerTracker never stores such material.')
        ]),
        h('button.btn.primary.block', { type: 'button', onClick: computeText }, [icon('hash'), 'Compute digests'])
      ]),
      h('div.card', [
        h('div.card-head', [icon('upload'), h('h3', 'Hash a local file')]),
        h('p.small.dim.mb12', 'The file is read in memory on this device only.'),
        h('input', {
          type: 'file', 'aria-label': 'File to hash',
          on: {
            change: function () {
              const f = this.files && this.files[0];
              if (!f) return;
              const reader = new FileReader();
              reader.onload = () => computeFrom(new Uint8Array(reader.result), f.name);
              reader.onerror = () => CT.dom.mount(out, CT.dom.notice('err', 'Could not read file', 'The file could not be read in this context.'));
              reader.readAsArrayBuffer(f);
            }
          }
        })
      ]),
      out
    ]);
  }

  /* ==========================================================================
     NOTES
     ======================================================================= */
  function notesTool() {
    const cur = CT.store.currentAssessment();
    const notes = CT.store.state.notes;
    return h('div.stack.gap12', [
      h('div.card', [
        h('div.card-head', [icon('note'), h('h3', 'Assessment notes')]),
        h('p.small.dim.mb12', cur
          ? 'New notes are attached to assessment #' + String(cur.number).padStart(3, '0') + '.'
          : 'Notes are stored locally and attached to whichever assessment is open.'),
        h('button.btn.primary.block', {
          type: 'button',
          onClick: () => S.prompt({ title: 'New note', label: 'Note', multiline: true, placeholder: 'Observation, follow-up, ticket reference…' })
            .then((v) => { if (v && v.trim()) { CT.store.addNote(v.trim()); S.toast('Note saved', 'ok'); S.render(); } })
        }, [icon('plus'), 'Add note'])
      ]),
      notes.length
        ? h('div.card.flush', h('div.list', notes.map((n) => {
          const a = CT.store.state.assessments.find((x) => x.id === n.assessmentId);
          return h('div.list-item.static', { style: { display: 'block' } }, [
            h('div.row.gap8', [
              h('span.tiny.muted.grow', CT.util.fmtDateTime(n.ts) + (a ? ' · #' + String(a.number).padStart(3, '0') : '')),
              h('button.btn.sm.quiet', {
                type: 'button', 'aria-label': 'Delete note',
                onClick: () => S.confirm({ title: 'Delete note?', body: 'This cannot be undone.', danger: true, confirmLabel: 'Delete' })
                  .then((ok) => { if (ok) { CT.store.deleteNote(n.id); S.render(); } })
              }, icon('trash'))
            ]),
            h('div.small.mt4', { style: { 'white-space': 'pre-wrap' } }, n.text)
          ]);
        })))
        : CT.dom.empty({ icon: 'note', title: 'No notes yet', body: 'Record observations that belong with the assessment but not with a single finding.' })
    ]);
  }

  const RENDER = {
    cidr: cidrTool, dns: dnsTool, tls: tlsTool, headers: headersTool,
    ports: portsTool, hash: hashTool, notes: notesTool
  };
})();
