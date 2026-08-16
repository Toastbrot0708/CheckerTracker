/* ============================================================================
   MODULE: CT.ui.routes.assets — inventory, asset detail, network map
   ========================================================================= */
(function () {
  'use strict';
  const h = CT.dom.h, icon = CT.dom.icon, S = CT.ui.shell;
  const SVG = 'http://www.w3.org/2000/svg';

  let as = { type: 'all', query: '', sort: 'risk' };

  /* ==========================================================================
     INVENTORY
     ======================================================================= */
  CT.ui.routes.assets = {
    parent: '#/more', tab: 'more', keepScroll: true,
    title: () => 'Assets',
    subtitle: () => CT.util.plural(CT.store.assets().length, 'device'),
    actions: () => h('button.icon-btn', { type: 'button', 'aria-label': 'Network map', onClick: () => S.navigate('#/map') }, icon('map')),
    render() {
      const cur = CT.store.currentAssessment();
      if (!cur) return S.emptyNoAssessment('the inventory');

      const findings = CT.store.findings();
      const all = CT.engines.risk.scoreAll(cur.assets, findings);
      const types = ['all'].concat(CT.data.DEVICE_TYPES.filter((t) => all.some((e) => e.asset.deviceType === t)));

      const listBox = h('div.card.flush');
      const countLine = h('div.tiny.muted');

      function matches(e) {
        if (as.type !== 'all' && e.asset.deviceType !== as.type) return false;
        const q = as.query.trim().toLowerCase();
        if (!q) return true;
        const a = e.asset;
        return [a.hostname, a.ip, a.ipv6, a.mac, a.vendor, a.os, a.owner, a.deviceType]
          .concat((a.services || []).map((s) => s.port + ' ' + s.name + ' ' + (s.product || '')))
          .filter(Boolean).join(' ').toLowerCase().indexOf(q) !== -1;
      }
      function sortFn(x, y) {
        if (as.sort === 'name') return String(x.asset.hostname || x.asset.ip).localeCompare(String(y.asset.hostname || y.asset.ip));
        if (as.sort === 'ip') return CT.net.ipToInt(x.asset.ip) - CT.net.ipToInt(y.asset.ip);
        if (as.sort === 'services') return (y.asset.services || []).length - (x.asset.services || []).length;
        if (as.sort === 'seen') return y.asset.lastSeen - x.asset.lastSeen;
        return y.risk.score - x.risk.score || CT.net.ipToInt(x.asset.ip) - CT.net.ipToInt(y.asset.ip);
      }

      const vlist = new CT.dom.VirtualList({
        scrollEl: S.els.view, itemHeight: 62, threshold: 60,
        renderItem: (e) => S.assetRow(e.asset, e.risk)
      });

      function refresh() {
        const filtered = all.filter(matches).sort(sortFn);
        countLine.textContent = filtered.length + ' of ' + all.length;
        CT.dom.clear(listBox);
        if (!filtered.length) {
          listBox.appendChild(CT.dom.empty({
            icon: 'server', title: 'No assets in this view',
            body: as.query ? 'Nothing matches "' + as.query + '".' : 'No device of this type was observed in the current assessment.',
            secondary: { label: 'Reset filters', onClick: () => { as = { type: 'all', query: '', sort: 'risk' }; S.render(); } }
          }));
        } else {
          listBox.appendChild(vlist.root);
          vlist.setItems(filtered);
          vlist.attach();
        }
      }

      const container = h('div.stack.gap10', [
        S.simulatedBanner(cur),
        h('div.search-bar', [
          icon('search'),
          h('input', {
            type: 'search', value: as.query, placeholder: 'IP, hostname, MAC, vendor, OS or service',
            'aria-label': 'Search assets',
            on: { input: CT.util.debounce(function () { as.query = this.value; refresh(); }, 140) }
          })
        ]),
        h('div.chips', { role: 'group', 'aria-label': 'Filter by device type' }, types.map((t) =>
          h('button.chip', {
            type: 'button', 'aria-pressed': as.type === t ? 'true' : 'false',
            onClick: () => { as.type = t; S.render(); }
          }, [
            h('span', t === 'all' ? 'All' : t),
            h('span.n', String(t === 'all' ? all.length : all.filter((e) => e.asset.deviceType === t).length))
          ]))),
        h('div.row.gap8', [
          h('div.segmented.grow', { role: 'group', 'aria-label': 'Sort assets' },
            [['risk', 'Risk'], ['ip', 'IP'], ['name', 'Name'], ['services', 'Services'], ['seen', 'Seen']].map(([id, label]) =>
              h('button', { type: 'button', 'aria-pressed': as.sort === id ? 'true' : 'false',
                onClick: () => { as.sort = id; refresh(); S.render(); } }, label)))
        ]),
        CT.dom.sectionLabel('Inventory', countLine),
        listBox
      ]);
      refresh();
      return container;
    }
  };

  /* ==========================================================================
     ASSET DETAIL
     ======================================================================= */
  CT.ui.routes.asset = {
    parent: '#/assets', tab: 'more',
    title: (p) => { const a = CT.store.assetById(p[0]); return a ? (a.hostname || a.ip) : 'Asset'; },
    subtitle: (p) => { const a = CT.store.assetById(p[0]); return a ? a.ip : null; },
    render(params) {
      const a = CT.store.assetById(params[0]);
      if (!a) {
        return CT.dom.empty({
          icon: 'server', title: 'Asset not found',
          body: 'This device is not part of the assessment currently loaded.',
          action: { label: 'Back to inventory', onClick: () => S.navigate('#/assets') }
        });
      }
      const findings = CT.store.findings();
      const risk = CT.engines.risk.scoreAsset(a, findings);
      const prevAssessment = CT.store.previousAssessment();
      const prev = prevAssessment ? prevAssessment.assets.find((x) => x.id === a.id) : null;
      const cur = CT.store.currentAssessment();
      const tlsSummary = CT.engines.tls.summarise(a.tls, a.hostname);

      return h('div.stack.gap12', [
        cur && cur.simulated ? h('div.demo-banner', [icon('alert'), h('div.grow',
          [h('strong', 'SIMULATED'), ' — this device exists only in the "' + cur.environmentName + '" demo environment.'])]) : null,

        h('div.card', [
          h('div.row.gap12', [
            h('span', { style: { color: 'var(--accent)', display: 'flex', flex: '0 0 auto' } }, S.deviceIcon(a.deviceType)),
            h('span.grow.stack', [
              h('span', { style: { 'font-size': '1.05em', 'font-weight': '680' } }, a.hostname || 'Unnamed device'),
              h('span.mono.small.muted', a.ip)
            ]),
            h('span.stack', { style: { 'align-items': 'flex-end' } }, [
              h('span.pill.' + (a.status === 'reachable' ? 'ok' : 'neutral'), a.status === 'reachable' ? 'Reachable' : 'Unreachable'),
              h('span.tiny.muted.mt4', CT.util.fmtRelative(a.lastSeen))
            ])
          ]),
          h('div.row.gap8.wrap.mt12', [
            h('span.pill.' + (risk.level === 'ok' ? 'ok' : risk.level), [
              h('span.glyph', { 'aria-hidden': 'true' }, risk.level === 'ok' ? '✓' : CT.data.SEV_GLYPH[risk.level]),
              h('span', risk.label + (risk.level === 'ok' ? '' : ' · ' + risk.score))
            ]),
            a.inInventory === false ? h('span.pill.medium', 'Not in inventory') : h('span.tag', 'In inventory'),
            a.criticality && a.criticality !== 'standard' ? h('span.tag', CT.util.titleCase(a.criticality) + ' criticality') : null,
            (a.tags || []).map((t) => h('span.tag', t))
          ])
        ]),

        card('Identity', 'user', h('dl', [
          CT.dom.kv('Hostname', a.hostname || 'not resolved', { mono: !!a.hostname }),
          CT.dom.kv('IPv4', a.ip, { mono: true }),
          CT.dom.kv('IPv6', a.ipv6 ? CT.net.compressIPv6(a.ipv6) : 'not observed', { mono: true }),
          CT.dom.kv('MAC', a.mac || 'not observed', { mono: true }),
          CT.dom.kv('Vendor (OUI)', a.vendor || 'not determined'),
          CT.dom.kv('Device type', a.deviceType),
          CT.dom.kv('Operating system', a.os ? a.os + (a.osConfidence ? '  (' + a.osConfidence + ' confidence)' : '') : 'not determined'),
          CT.dom.kv('Owner', a.owner || 'unassigned'),
          CT.dom.kv('First seen', CT.util.fmtDateTime(a.firstSeen)),
          CT.dom.kv('Last seen', CT.util.fmtDateTime(a.lastSeen))
        ])),

        card('Services', 'layers', servicesTable(a)),

        card('Security', 'shield', securitySection(a, tlsSummary, risk)),

        card('Findings (' + risk.findings.length + ')', 'alert',
          risk.findings.length
            ? h('div.list', risk.findings.map((f) => S.findingRow(f)))
            : h('div.row.gap8', [
              h('span.status-dot.ok', { 'aria-hidden': 'true' }),
              h('span.small.dim', 'No findings recorded for this asset in the current assessment.')
            ])),

        card('History', 'clock', historySection(a, prev, prevAssessment, cur)),

        h('div.btn-grid', [
          h('button.btn', { type: 'button', onClick: () => S.navigate('#/map') }, [icon('map'), 'View in map']),
          h('button.btn', {
            type: 'button',
            onClick: () => S.guardedExport({
              filename: (a.hostname || a.ip).replace(/[^\w.-]/g, '_') + '.json',
              mime: 'application/json',
              title: 'Export asset',
              summary: 'single asset record',
              content: JSON.stringify({
                tool: 'CheckerTracker', schema: 'checkertracker.asset/1',
                exportedAt: new Date().toISOString(),
                dataOrigin: (cur && cur.simulated) ? 'SIMULATED — demo environment' : 'Observed',
                asset: a,
                findings: risk.findings.map((f) => ({ id: f.id, ruleId: f.ruleId, title: f.title, severity: f.severity, status: f.status }))
              }, null, 2)
            })
          }, [icon('download'), 'Export'])
        ])
      ]);
    }
  };

  function card(title, iconName, content, extra) {
    return h('div.card', [h('div.card-head', [icon(iconName), h('h3', title), extra || null]), content]);
  }

  function servicesTable(a) {
    const services = a.services || [];
    if (!services.length) {
      return h('div.row.gap8', [
        h('span.status-dot.ok', { 'aria-hidden': 'true' }),
        h('span.small.dim', 'No listening services were observed on this device.')
      ]);
    }
    return h('div.tbl-wrap', h('table.tbl', [
      h('thead', h('tr', [h('th', 'Port'), h('th', 'Service'), h('th', 'Version'), h('th', 'Exposure'), h('th', 'Risk')])),
      h('tbody', services.map((s) => {
        const ref = CT.data.portInfo(s.port);
        const admin = ref && ref.admin;
        const enc = ref ? ref.encrypted : null;
        const riskLabel = admin ? 'Review recommended' : enc ? 'Secure' : ref ? 'Standard' : 'Unclassified';
        const riskKind = admin ? 'medium' : enc ? 'ok' : 'info';
        return h('tr.clickable', {
          onClick: () => portSheet(s, a),
          tabindex: '0',
          on: { keydown: (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); portSheet(s, a); } } }
        }, [
          h('td', h('span.mono', { style: { 'font-weight': '650' } }, s.port + '/' + s.proto)),
          h('td', [h('div', { style: { 'font-weight': '600' } }, ref ? ref.name : (s.name || 'unknown')),
                   h('div.tiny.muted', ref ? ref.service : 'Unidentified')]),
          h('td', s.product ? h('div', [h('div', s.product), s.version ? h('div.tiny.muted.mono', s.version) : null]) : h('span.muted', '—')),
          h('td', h('span.tiny', enc === true ? 'Encrypted' : enc === false ? 'Cleartext' : '—')),
          h('td', h('span.pill.' + riskKind, riskLabel))
        ]);
      }))
    ]));
  }

  function portSheet(s, a) {
    const ref = CT.data.portInfo(s.port);
    S.sheet({
      title: s.port + '/' + s.proto + (ref ? ' · ' + ref.name : ''),
      body: h('div.stack.gap12', [
        h('dl', [
          CT.dom.kv('Host', (a.hostname || '') + ' ' + a.ip, { mono: true }),
          CT.dom.kv('Port', s.port + '/' + s.proto, { mono: true }),
          CT.dom.kv('Service', ref ? ref.service : 'Unidentified'),
          CT.dom.kv('Product', s.product || '—'),
          CT.dom.kv('Version', s.version ? s.version + (s.versionConfidence ? ' (' + s.versionConfidence + ' confidence)' : '') : '—'),
          CT.dom.kv('Category', ref ? ref.category : '—'),
          CT.dom.kv('Transport encryption', ref ? (ref.encrypted ? 'Yes' : 'No') : 'Unknown'),
          CT.dom.kv('Administrative', ref ? (ref.admin ? 'Yes' : 'No') : 'Unknown')
        ]),
        s.banner ? h('div', [CT.dom.sectionLabel('Banner'), h('pre.code.wrap-lines', s.banner)]) : null,
        ref ? CT.dom.notice(null, 'Reference note', ref.note) : null
      ])
    });
  }

  function securitySection(a, tlsSummary, risk) {
    const rows = [];
    const c = a.tls && a.tls.cert;

    rows.push(h('div', [
      CT.dom.sectionLabel('Transport security'),
      h('dl', [
        CT.dom.kv('TLS status', h('span.row.gap6', { style: { 'justify-content': 'flex-end' } }, [
          h('span.status-dot.' + (tlsSummary.kind === 'ok' ? 'ok' : tlsSummary.kind === 'warn' ? 'medium' : tlsSummary.kind === 'bad' ? 'critical' : 'info'), { 'aria-hidden': 'true' }),
          h('span', tlsSummary.label)
        ])),
        a.tls ? CT.dom.kv('Protocols', (a.tls.protocols || []).join(', '), { mono: true }) : null,
        a.tls ? CT.dom.kv('Cipher', a.tls.cipher || '—', { mono: true }) : null
      ])
    ]));

    if (c) {
      const days = Math.floor((c.notAfter - Date.now()) / 86400000);
      rows.push(h('div.mt12', [
        CT.dom.sectionLabel('Certificate'),
        h('dl', [
          CT.dom.kv('Subject', c.subjectCN || '—', { mono: true }),
          CT.dom.kv('Issuer', c.issuerCN || '—'),
          CT.dom.kv('Valid from', CT.util.fmtDate(c.notBefore)),
          CT.dom.kv('Expires', h('span.row.gap6', { style: { 'justify-content': 'flex-end' } }, [
            h('span.status-dot.' + (days < 0 ? 'critical' : days < 30 ? 'medium' : 'ok'), { 'aria-hidden': 'true' }),
            h('span', CT.util.fmtDate(c.notAfter) + (days < 0 ? ' (expired)' : ' (' + days + ' days)'))
          ])),
          CT.dom.kv('Signature', c.sigAlg, { mono: true }),
          CT.dom.kv('Key', (c.keyAlg || '') + ' ' + (c.keyBits ? c.keyBits + '-bit' : ''), { mono: true }),
          CT.dom.kv('Self-signed', c.selfSigned ? 'Yes' : 'No'),
          CT.dom.kv('SAN', (c.san || []).join(', ') || '—', { mono: true })
        ])
      ]));
    }

    if (a.http) {
      const report = CT.engines.web.headerReport(a.http);
      rows.push(h('div.mt12', [
        CT.dom.sectionLabel('Security headers'),
        h('div.tbl-wrap', h('table.tbl', [
          h('thead', h('tr', [h('th', 'Header'), h('th', 'State'), h('th', 'Value')])),
          h('tbody', report.map((r) => h('tr', [
            h('td', r.label),
            h('td', h('span.pill.' + (r.state === 'ok' ? 'ok' : r.state === 'missing' ? 'medium' : r.state === 'weak' ? 'medium' : 'info'),
              r.state === 'ok' ? 'Set' : r.state === 'missing' ? 'Missing' : r.state === 'weak' ? 'Weak' : r.state === 'na' ? 'N/A' : 'Info')),
            h('td', h('span.tiny.mono', { style: { 'word-break': 'break-all' } }, r.note))
          ])))
        ]))
      ]));
    }

    const adminSvcs = (a.services || []).filter((s) => { const r = CT.data.portInfo(s.port); return r && r.admin; });
    rows.push(h('div.mt12', [
      CT.dom.sectionLabel('Authentication exposure'),
      adminSvcs.length
        ? h('div', [
          h('p.tiny.muted.mb6', { style: { margin: '0 0 6px' } }, 'Services that front an authentication boundary. CheckerTracker never submits credentials to them.'),
          h('div.list', adminSvcs.map((s) => {
            const r = CT.data.portInfo(s.port);
            return h('div.list-item.static', [
              h('span.mono.small', { style: { flex: '0 0 82px' } }, s.port + '/' + s.proto),
              h('span.grow.stack', [h('span.small', r.name), h('span.tiny.muted', r.encrypted ? 'Encrypted transport' : 'Cleartext transport')]),
              h('span.pill.' + (r.encrypted ? 'medium' : 'high'), r.encrypted ? 'Restrict' : 'Cleartext')
            ]);
          }))
        ])
        : h('div.row.gap8', [h('span.status-dot.ok', { 'aria-hidden': 'true' }), h('span.small.dim', 'No administrative service observed.')])
    ]));

    const checks = configChecks(a, risk);
    rows.push(h('div.mt12', [
      CT.dom.sectionLabel('Configuration checks'),
      h('div.list', checks.map((c2) => h('div.list-item.static', [
        h('span.status-dot.' + (c2.pass ? 'ok' : c2.severity === 'high' || c2.severity === 'critical' ? 'critical' : 'medium'), { 'aria-hidden': 'true' }),
        h('span.grow.small', c2.label),
        h('span.tiny', { style: { color: c2.pass ? 'var(--ok)' : 'var(--sev-medium)', 'font-weight': '650' } }, c2.pass ? 'Pass' : 'Review')
      ])))
    ]));

    return h('div', rows);
  }

  function configChecks(a, risk) {
    const has = (rule) => risk.findings.some((f) => f.ruleId === rule);
    const services = a.services || [];
    const out = [
      { label: 'No cleartext management protocol reachable', pass: !has('CT-NET-002'), severity: 'high' },
      { label: 'No remote desktop service exposed', pass: !has('CT-CFG-003'), severity: 'high' },
      { label: 'Device present in expected inventory', pass: a.inInventory !== false, severity: 'medium' },
      { label: 'No factory default configuration indicator', pass: !has('CT-CFG-001'), severity: 'medium' },
      { label: 'Software versions within supported branch', pass: !has('CT-CFG-002'), severity: 'medium' }
    ];
    if (a.tls) {
      out.push({ label: 'Certificate valid and not expiring soon', pass: !has('CT-TLS-001') && !has('CT-TLS-002'), severity: 'critical' });
      out.push({ label: 'Only TLS 1.2 or newer enabled', pass: !has('CT-TLS-003'), severity: 'high' });
      out.push({ label: 'Certificate issued by a trusted CA', pass: !has('CT-TLS-005'), severity: 'medium' });
      out.push({ label: 'Modern signature algorithm and key size', pass: !has('CT-TLS-006') && !has('CT-TLS-007'), severity: 'high' });
    }
    if (a.http) {
      out.push({ label: 'Core security headers present', pass: !has('CT-WEB-001') && !has('CT-WEB-002') && !has('CT-WEB-003'), severity: 'medium' });
      out.push({ label: 'Cookies carry protective attributes', pass: !has('CT-WEB-006'), severity: 'medium' });
      out.push({ label: 'No product version disclosure', pass: !has('CT-WEB-007'), severity: 'low' });
    }
    if (services.some((s) => s.port === 445)) {
      out.push({ label: 'Modern SMB dialect only', pass: !has('CT-NET-003'), severity: 'high' });
    }
    return out;
  }

  function historySection(a, prev, prevAssessment, cur) {
    const events = CT.engines.assetdb.assetHistory(a, prev,
      prevAssessment ? prevAssessment.endedAt : null, cur ? cur.endedAt : Date.now());

    const riskLine = [];
    if (prev && prevAssessment && cur) {
      const prevRisk = CT.engines.risk.scoreAsset(prev, prevAssessment.findings);
      const nowRisk = CT.engines.risk.scoreAsset(a, CT.store.findings());
      if (prevRisk.score !== nowRisk.score) {
        riskLine.push({
          ts: cur.endedAt,
          kind: nowRisk.score > prevRisk.score ? 'bad' : 'ok',
          text: 'Risk score changed from ' + prevRisk.score + ' to ' + nowRisk.score
        });
      }
    }
    const all = riskLine.concat(events).sort((x, y) => y.ts - x.ts).slice(0, 14);
    if (!all.length) return h('p.small.muted', 'No recorded changes for this asset.');
    return h('div.timeline', all.map((e) => h('div.tl-item', { dataset: { kind: e.kind } }, [
      h('div.t', e.text),
      h('div.m', CT.util.fmtRelative(e.ts) + ' · ' + CT.util.fmtDateTime(e.ts))
    ])));
  }

  /* ==========================================================================
     NETWORK MAP
     ======================================================================= */
  const GROUP_ORDER = [
    { id: 'network', label: 'Network devices' },
    { id: 'servers', label: 'Servers / NAS' },
    { id: 'workstations', label: 'Workstations' },
    { id: 'mobile', label: 'Mobile' },
    { id: 'iot', label: 'IoT / printers / cameras' },
    { id: 'unknown', label: 'Unknown' }
  ];
  const RISK_COLOR = { ok: '#35C08E', low: '#58B0F0', medium: '#F5C451', high: '#FF9440', critical: '#FF5A63' };

  CT.ui.routes.map = {
    parent: '#/more', tab: 'more',
    title: () => 'Network map',
    subtitle: () => { const n = CT.store.network(); return n ? n.subnet : null; },
    render() {
      const cur = CT.store.currentAssessment();
      if (!cur) return S.emptyNoAssessment('the map');
      const findings = CT.store.findings();
      const assets = cur.assets;
      const gateway = cur.network ? assets.find((a) => a.ip === cur.network.gateway) : null;
      const nodes = CT.engines.risk.scoreAll(assets.filter((a) => a !== gateway), findings)
        .map((e) => ({ asset: e.asset, risk: e.risk, group: CT.data.DEVICE_GROUP[e.asset.deviceType] || 'unknown' }));

      const stage = h('div.map-stage', { role: 'group', 'aria-label': 'Network topology map' });
      const svg = document.createElementNS(SVG, 'svg');
      svg.setAttribute('viewBox', '0 0 800 800');
      svg.setAttribute('preserveAspectRatio', 'xMidYMid meet');
      const root = document.createElementNS(SVG, 'g');
      svg.appendChild(root);
      stage.appendChild(svg);

      layout(root, nodes, gateway, cur);

      /* Pan & zoom */
      let scale = 1, tx = 0, ty = 0, dragging = false, lx = 0, ly = 0, moved = false;
      function apply() { root.setAttribute('transform', 'translate(' + tx + ',' + ty + ') scale(' + scale + ')'); }
      stage.addEventListener('pointerdown', (e) => {
        dragging = true; moved = false; lx = e.clientX; ly = e.clientY;
        stage.setPointerCapture(e.pointerId);
      });
      stage.addEventListener('pointermove', (e) => {
        if (!dragging) return;
        const dx = e.clientX - lx, dy = e.clientY - ly;
        if (Math.abs(dx) + Math.abs(dy) > 3) moved = true;
        const k = 800 / stage.clientWidth;
        tx += dx * k; ty += dy * k; lx = e.clientX; ly = e.clientY;
        apply();
      });
      const endDrag = (e) => { dragging = false; try { stage.releasePointerCapture(e.pointerId); } catch (err) { /* noop */ } };
      stage.addEventListener('pointerup', endDrag);
      stage.addEventListener('pointercancel', endDrag);
      stage.addEventListener('click', (e) => { if (moved) { e.stopPropagation(); e.preventDefault(); } }, true);
      stage.addEventListener('wheel', (e) => {
        e.preventDefault();
        const f = e.deltaY < 0 ? 1.12 : 1 / 1.12;
        scale = CT.util.clamp(scale * f, 0.4, 4);
        apply();
      }, { passive: false });

      stage.appendChild(h('div.map-hint', 'Drag to pan · pinch or scroll to zoom · tap a node'));
      stage.appendChild(h('div.map-controls', [
        h('button', { type: 'button', 'aria-label': 'Zoom in', onClick: () => { scale = CT.util.clamp(scale * 1.25, 0.4, 4); apply(); } }, '+'),
        h('button', { type: 'button', 'aria-label': 'Zoom out', onClick: () => { scale = CT.util.clamp(scale / 1.25, 0.4, 4); apply(); } }, '−'),
        h('button', { type: 'button', 'aria-label': 'Reset view', onClick: () => { scale = 1; tx = 0; ty = 0; apply(); } }, '⌂')
      ]));

      const counts = {};
      nodes.forEach((n) => { counts[n.risk.level] = (counts[n.risk.level] || 0) + 1; });

      return h('div.stack.gap12', [
        S.simulatedBanner(cur),
        stage,
        h('div.map-legend', [
          h('span', [h('span.status-dot.ok', { 'aria-hidden': 'true' }), 'Normal (' + (counts.ok || 0) + ')']),
          h('span', [h('span.status-dot.low', { 'aria-hidden': 'true' }), 'Low (' + (counts.low || 0) + ')']),
          h('span', [h('span.status-dot.medium', { 'aria-hidden': 'true' }), 'Warning (' + (counts.medium || 0) + ')']),
          h('span', [h('span.status-dot.high', { 'aria-hidden': 'true' }), 'High (' + (counts.high || 0) + ')']),
          h('span', [h('span.status-dot.critical', { 'aria-hidden': 'true' }), 'Critical (' + (counts.critical || 0) + ')'])
        ]),
        h('p.tiny.muted', 'Node size reflects the number of listening services. Nodes are grouped by device class around the gateway. Risk is shown by colour and by the ring around each node, so the map stays readable without relying on colour alone.'),
        h('div.card', [
          h('div.card-head', [icon('list'), h('h3', 'Groups')]),
          h('div.list', GROUP_ORDER.filter((g) => nodes.some((n) => n.group === g.id)).map((g) => {
            const items = nodes.filter((n) => n.group === g.id);
            const worst = items.reduce((acc, n) => Math.min(acc, CT.data.SEV_RANK[n.risk.level] === undefined ? 9 : CT.data.SEV_RANK[n.risk.level]), 9);
            return h('div.list-item.static', [
              h('span.grow.small', g.label),
              h('span.tag', CT.util.plural(items.length, 'device')),
              worst <= 1 ? h('span.pill.high', 'attention') : null
            ]);
          }))
        ])
      ]);
    }
  };

  function layout(root, nodes, gateway, assessment) {
    const cx = 400, cy = 400;
    const total = nodes.length || 1;

    // Ring geometry adapts to density so a 500-node estate still fits inside
    // the 800×800 viewBox without the user having to zoom out to find it.
    const geom = total <= 40 ? { R0: 130, RG: 62, SPACING: 46, scale: 1 }
      : total <= 120 ? { R0: 112, RG: 40, SPACING: 30, scale: 0.72 }
        : total <= 300 ? { R0: 100, RG: 28, SPACING: 21, scale: 0.55 }
          : { R0: 90, RG: 22, SPACING: 17, scale: 0.45 };
    const R0 = geom.R0, RG = geom.RG, SPACING = geom.SPACING;

    const groups = GROUP_ORDER.map((g) => ({ id: g.id, label: g.label, items: nodes.filter((n) => n.group === g.id) }))
      .filter((g) => g.items.length);

    const edges = document.createElementNS(SVG, 'g');
    const dots = document.createElementNS(SVG, 'g');
    root.appendChild(edges);
    root.appendChild(dots);

    // Gateway ring guides
    [R0, R0 + RG, R0 + RG * 2].forEach((r) => {
      const c = document.createElementNS(SVG, 'circle');
      c.setAttribute('cx', cx); c.setAttribute('cy', cy); c.setAttribute('r', r);
      c.setAttribute('fill', 'none'); c.setAttribute('stroke', '#1E273A'); c.setAttribute('stroke-width', '1');
      edges.appendChild(c);
    });

    let angle = -Math.PI / 2;
    groups.forEach((g) => {
      const span = (2 * Math.PI * g.items.length) / total;
      let placed = 0, ring = 0;
      while (placed < g.items.length && ring < 40) {
        const radius = R0 + ring * RG;
        const capacity = Math.max(1, Math.floor((span * radius) / SPACING));
        const take = Math.min(capacity, g.items.length - placed);
        for (let i = 0; i < take; i++) {
          const t = take === 1 ? 0.5 : (i + 0.5) / take;
          const ang = angle + span * t;
          const x = cx + radius * Math.cos(ang);
          const y = cy + radius * Math.sin(ang);
          drawNode(dots, edges, g.items[placed + i], x, y, cx, cy, geom.scale);
        }
        placed += take;
        ring++;
      }
      angle += span;
    });

    // Gateway node last so it renders on top
    const gw = document.createElementNS(SVG, 'g');
    const gwCircle = document.createElementNS(SVG, 'circle');
    gwCircle.setAttribute('cx', cx); gwCircle.setAttribute('cy', cy); gwCircle.setAttribute('r', 30);
    gwCircle.setAttribute('fill', '#131926');
    gwCircle.setAttribute('stroke', '#4C8DFF'); gwCircle.setAttribute('stroke-width', '2.5');
    gw.appendChild(gwCircle);
    const gwText = document.createElementNS(SVG, 'text');
    gwText.setAttribute('x', cx); gwText.setAttribute('y', cy + 4);
    gwText.setAttribute('text-anchor', 'middle');
    gwText.setAttribute('fill', '#E9EDF5');
    gwText.setAttribute('font-size', '12'); gwText.setAttribute('font-weight', '700');
    gwText.setAttribute('font-family', 'system-ui, sans-serif');
    gwText.textContent = 'GW';
    gw.appendChild(gwText);
    const gwLabel = document.createElementNS(SVG, 'text');
    gwLabel.setAttribute('x', cx); gwLabel.setAttribute('y', cy + 48);
    gwLabel.setAttribute('text-anchor', 'middle');
    gwLabel.setAttribute('fill', '#78839A');
    gwLabel.setAttribute('font-size', '11');
    gwLabel.setAttribute('font-family', 'ui-monospace, monospace');
    gwLabel.textContent = (assessment.network && assessment.network.gateway) || 'gateway';
    gw.appendChild(gwLabel);
    if (gateway) {
      gw.setAttribute('class', 'map-node');
      gw.setAttribute('tabindex', '0');
      gw.setAttribute('role', 'button');
      gw.setAttribute('aria-label', 'Gateway ' + (gateway.hostname || gateway.ip));
      gw.addEventListener('click', () => S.navigate('#/asset/' + gateway.id));
      gw.addEventListener('keydown', (e) => { if (e.key === 'Enter') S.navigate('#/asset/' + gateway.id); });
    }
    root.appendChild(gw);
  }

  function drawNode(dots, edges, n, x, y, cx, cy, scale) {
    const a = n.asset;
    const k = scale || 1;
    const svcCount = (a.services || []).length;
    const r = CT.util.clamp(7 + svcCount * 1.15, 7, 15) * k;
    const color = RISK_COLOR[n.risk.level] || RISK_COLOR.ok;

    const line = document.createElementNS(SVG, 'line');
    line.setAttribute('x1', cx); line.setAttribute('y1', cy);
    line.setAttribute('x2', x); line.setAttribute('y2', y);
    line.setAttribute('stroke', '#1E273A');
    line.setAttribute('stroke-width', '1');
    edges.appendChild(line);

    const g = document.createElementNS(SVG, 'g');
    g.setAttribute('class', 'map-node');
    g.setAttribute('tabindex', '0');
    g.setAttribute('role', 'button');
    g.setAttribute('aria-label', (a.hostname || a.ip) + ', ' + a.deviceType + ', ' + n.risk.label +
      ', ' + CT.util.plural(svcCount, 'service'));

    const hit = document.createElementNS(SVG, 'circle');
    hit.setAttribute('class', 'hit');
    hit.setAttribute('cx', x); hit.setAttribute('cy', y); hit.setAttribute('r', r + 9 * k);
    hit.setAttribute('fill', 'transparent');
    hit.setAttribute('stroke', 'transparent');
    g.appendChild(hit);

    // Risk ring: distinct stroke pattern per level so colour is not the only cue.
    if (n.risk.level !== 'ok') {
      const ring = document.createElementNS(SVG, 'circle');
      ring.setAttribute('cx', x); ring.setAttribute('cy', y); ring.setAttribute('r', r + 4.5 * k);
      ring.setAttribute('fill', 'none');
      ring.setAttribute('stroke', color);
      ring.setAttribute('stroke-width', String((n.risk.level === 'critical' ? 2.4 : n.risk.level === 'high' ? 1.8 : 1.2) * Math.max(k, 0.7)));
      ring.setAttribute('stroke-opacity', '0.85');
      if (n.risk.level === 'medium') ring.setAttribute('stroke-dasharray', '3 3');
      if (n.risk.level === 'low') ring.setAttribute('stroke-dasharray', '1.5 4');
      g.appendChild(ring);
    }

    const c = document.createElementNS(SVG, 'circle');
    c.setAttribute('cx', x); c.setAttribute('cy', y); c.setAttribute('r', r);
    c.setAttribute('fill', n.risk.level === 'ok' ? '#1E273A' : color);
    c.setAttribute('fill-opacity', n.risk.level === 'ok' ? '1' : '0.9');
    c.setAttribute('stroke', n.risk.level === 'ok' ? '#2C374B' : color);
    c.setAttribute('stroke-width', '1.5');
    g.appendChild(c);

    if (a.inInventory === false && k > 0.5) {
      const q = document.createElementNS(SVG, 'text');
      q.setAttribute('x', x); q.setAttribute('y', y + 4 * k);
      q.setAttribute('text-anchor', 'middle');
      q.setAttribute('fill', '#0A0D13');
      q.setAttribute('font-size', String(11 * k)); q.setAttribute('font-weight', '800');
      q.setAttribute('font-family', 'system-ui, sans-serif');
      q.textContent = '?';
      g.appendChild(q);
    }

    const title = document.createElementNS(SVG, 'title');
    title.textContent = (a.hostname || a.ip) + '\n' + a.ip + '\n' + a.deviceType + '\n' + n.risk.label;
    g.appendChild(title);

    g.addEventListener('click', () => S.navigate('#/asset/' + a.id));
    g.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); S.navigate('#/asset/' + a.id); } });
    dots.appendChild(g);
  }
})();
