/* ============================================================================
   MODULE: CT.ui.routes — Dashboard, Security Score, Discover, More
   ========================================================================= */
CT.ui.routes = CT.ui.routes || {};

(function () {
  'use strict';
  const h = CT.dom.h, icon = CT.dom.icon, S = CT.ui.shell;

  const SCORE_COLOR = { ok: 'var(--ok)', warn: 'var(--sev-medium)', bad: 'var(--sev-high)', crit: 'var(--sev-critical)' };

  function scoreCard(score, opts) {
    const o = opts || {};
    const color = SCORE_COLOR[score.grade.kind];
    return h('div.card', [
      h('div.score-card', [
        h('div.gauge', [
          CT.dom.progressRing(score.score, { size: 116, stroke: 9, color }),
          h('div.val', [
            h('b', { style: { color } }, String(score.score)),
            h('em', 'of 100')
          ])
        ]),
        h('div.grow.stack.gap6', [
          h('div.row.gap8', [
            h('span.pill.' + (score.grade.kind === 'ok' ? 'ok' : score.grade.kind === 'warn' ? 'medium' : score.grade.kind === 'bad' ? 'high' : 'critical'),
              score.grade.label),
            h('span.tiny.muted', 'Security score')
          ]),
          h('div', { style: { 'font-size': '0.92em', 'font-weight': '600' } },
            score.attention === 0
              ? 'No critical or high findings'
              : CT.util.plural(score.attention, 'finding') + ' require attention'),
          h('div.tiny.muted', CT.util.plural(score.totalFindings, 'open finding') + ' in total'),
          o.hideLink ? null : h('button.btn.sm.ghost.mt4', { type: 'button', onClick: () => S.navigate('#/score') },
            ['How this is calculated', icon('chevronRight')])
        ])
      ])
    ]);
  }

  function breakdownList(score) {
    return h('div', score.breakdown.map((d) => h('div.breakdown-row', [
      h('span.name', d.label),
      CT.dom.bar(d.pct, d.pct >= 85 ? 'ok' : d.pct >= 65 ? 'warn' : d.pct >= 40 ? 'bad' : 'crit'),
      h('span.pct', d.pct + '%')
    ])));
  }

  function recentActivity() {
    const cur = CT.store.currentAssessment();
    const items = [];
    if (cur) {
      const num = '#' + String(cur.number).padStart(3, '0');
      const span = cur.durationMs || 1;
      items.push({ ts: cur.startedAt, kind: 'info', text: 'Assessment ' + num + ' started', meta: cur.scopeLabel + ' · ' + cur.profileName });
      items.push({ ts: cur.startedAt + span * 0.25, kind: 'ok', text: 'Network discovery completed', meta: CT.util.plural(cur.stats.hosts, 'host') + ' responding' });
      items.push({ ts: cur.startedAt + span * 0.35, kind: 'info', text: CT.util.plural(cur.stats.hosts, 'asset') + ' discovered', meta: cur.environmentName });
      if (cur.stats.services) {
        items.push({ ts: cur.startedAt + span * 0.6, kind: 'info', text: 'Port/service inventory updated', meta: CT.util.plural(cur.stats.services, 'service') + ' catalogued' });
      }
      const cfg = cur.findings.filter((f) => f.category === 'Configuration' || f.category === 'Web').length;
      if (cfg) items.push({ ts: cur.startedAt + span * 0.85, kind: 'warn', text: CT.util.plural(cfg, 'configuration finding') + ' detected', meta: 'Analyzer' });
      const crit = cur.findings.filter((f) => f.severity === 'critical').length;
      if (crit) items.push({ ts: cur.startedAt + span * 0.9, kind: 'bad', text: CT.util.plural(crit, 'critical finding') + ' detected', meta: 'Requires immediate review' });
      items.push({ ts: cur.endedAt, kind: 'ok', text: 'Risk score generated: ' + cur.score.score + '/100', meta: cur.score.grade.label });
    }
    CT.store.state.audit.slice(0, 12).forEach((a) => {
      if (a.action === 'scan.complete') return;
      const kind = a.action.indexOf('export') === 0 ? 'info'
        : a.action.indexOf('finding') === 0 ? 'ok'
          : a.action.indexOf('authorization') === 0 ? 'info' : 'info';
      items.push({ ts: a.ts, kind, text: auditLabel(a), meta: CT.util.fmtTime(a.ts) });
    });
    return items.sort((a, b) => b.ts - a.ts).slice(0, 8);
  }

  const AUDIT_LABEL = {
    'export': 'Report exported', 'demo.load': 'Demo environment loaded',
    'finding.status': 'Finding status updated', 'finding.note': 'Note added to a finding',
    'finding.assign': 'Finding assigned', 'authorization.grant': 'Authorization window opened',
    'authorization.revoke': 'Authorization window cleared', 'settings.change': 'Setting changed',
    'vault.enable': 'At-rest encryption enabled', 'vault.disable': 'At-rest encryption disabled',
    'vault.unlock': 'Encrypted store unlocked', 'note.add': 'Assessment note added',
    'note.delete': 'Assessment note deleted', 'scope.save': 'Scope saved',
    'assessment.import': 'Assessment imported', 'app.reset': 'Local data cleared',
    'app.start': 'Started with an empty environment', 'report.generate': 'Report generated',
    'tool.run': 'Tool executed', 'environment.select': 'Environment changed'
  };
  function auditLabel(a) { return AUDIT_LABEL[a.action] || CT.util.titleCase(a.action.replace(/\./g, ' ')); }

  function timeline(items) {
    return h('div.timeline', items.map((i) => h('div.tl-item', { dataset: { kind: i.kind } }, [
      h('div.t', i.text),
      h('div.m', [CT.util.fmtRelative(i.ts), i.meta ? ' · ' + i.meta : ''])
    ])));
  }

  /* ==========================================================================
     DASHBOARD
     ======================================================================= */
  CT.ui.routes.dashboard = {
    tab: 'dashboard',
    title: () => 'CheckerTracker',
    subtitle: () => 'Security visibility for authorized environments',
    render() {
      const cur = CT.store.currentAssessment();
      if (!cur) return dashboardEmpty();

      const assets = CT.store.assets();
      const findings = CT.store.findings();
      const active = findings.filter((f) => f.status !== 'resolved' && f.status !== 'accepted');
      const score = CT.store.liveScore();
      const counts = CT.engines.risk.countBySeverity(active);
      const net = cur.network;
      const services = assets.reduce((a, x) => a + (x.services || []).length, 0);
      const reachable = assets.filter((a) => a.status !== 'unreachable').length;
      const networks = new Set(CT.store.state.assessments.map((a) => (a.network && a.network.subnet) || a.scopeLabel)).size;
      const running = CT.engines.scanner.currentRun();

      return h('div.stack.gap12', [
        S.simulatedBanner(cur),

        CT.store.persistFailed() ? CT.dom.notice('warn', 'Results are not being saved',
          'The browser refused to write to local storage — usually the per-site quota, which a 500-asset environment can exceed. Everything works for this session but will be lost on reload. Export anything you need, or switch to a smaller environment.') : null,

        running ? h('button.card.tight', {
          type: 'button', style: { width: '100%', 'text-align': 'left', cursor: 'pointer' },
          onClick: () => S.navigate('#/scan')
        }, h('div.row.gap10', [
          h('span.status-dot.info', { 'aria-hidden': 'true' }),
          h('span.grow', [h('div', { style: { 'font-size': '0.88em', 'font-weight': '620' } }, 'Assessment running'),
                          h('div.tiny.muted', running.scopeLabel + ' · ' + running.progress + '%')]),
          icon('chevronRight', { cls: 'chev' })
        ])) : null,

        scoreCard(score),

        h('div', [
          CT.dom.sectionLabel('Environment'),
          h('div.metric-grid', [
            S.metric(assets.length, 'Devices', null, () => S.navigate('#/assets')),
            S.metric(reachable, 'Active hosts', null, () => S.navigate('#/assets')),
            S.metric(services, 'Open services', null, () => S.navigate('#/assets'))
          ]),
          h('div.metric-grid.c2.mt8', [
            S.metric(networks, 'Networks known'),
            S.metric(active.length, 'Open findings', null, () => S.navigate('#/findings'))
          ])
        ]),

        h('div', [
          CT.dom.sectionLabel('Findings by severity'),
          h('div.metric-grid.c2', [
            S.metric(counts.critical, 'Critical', 'crit', () => S.navigate('#/findings/critical')),
            S.metric(counts.high, 'High', 'high', () => S.navigate('#/findings/high'))
          ]),
          h('div.metric-grid.mt8', [
            S.metric(counts.medium, 'Medium', 'med', () => S.navigate('#/findings/medium')),
            S.metric(counts.low, 'Low', 'low', () => S.navigate('#/findings/low')),
            S.metric(counts.informational, 'Info', 'info', () => S.navigate('#/findings/informational'))
          ]),
          active.length ? h('div.card.tight.mt8', S.severityBar(counts, active.length)) : null
        ]),

        h('div.card', [
          h('div.card-head', [icon('clock'), h('h3', 'Last assessment')]),
          h('dl', [
            CT.dom.kv('Assessment', '#' + String(cur.number).padStart(3, '0') + ' · ' + cur.profileName),
            CT.dom.kv('Completed', CT.util.fmtDateTime(cur.endedAt) + ' (' + CT.util.fmtRelative(cur.endedAt) + ')'),
            CT.dom.kv('Duration', CT.util.fmtClock(cur.durationMs), { mono: true }),
            CT.dom.kv('Scope', cur.scopeLabel, { mono: true }),
            CT.dom.kv('Scan status', h('span.row.gap6', { style: { 'justify-content': 'flex-end' } }, [
              h('span.status-dot.' + (running ? 'info' : 'ok'), { 'aria-hidden': 'true' }),
              h('span', running ? 'Running' : 'Idle — completed')
            ])),
            CT.dom.kv('Data origin', cur.simulated ? h('span.demo-chip', 'Simulated') : 'Observed')
          ]),
          h('div.btn-row.mt12', [
            h('button.btn.sm.ghost', { type: 'button', onClick: () => S.navigate('#/history') }, [icon('clock'), 'History']),
            h('button.btn.sm.ghost', { type: 'button', onClick: () => S.navigate('#/compare') }, [icon('compare'), 'Compare'])
          ])
        ]),

        net ? h('div.card', [
          h('div.card-head', [icon('wifi'), h('h3', 'Network overview'),
            h('button.btn.sm.quiet', { type: 'button', onClick: () => S.navigate('#/discover') }, 'Details')]),
          h('dl', [
            CT.dom.kv('Network', net.name),
            net.ssid ? CT.dom.kv('SSID', net.ssid) : null,
            CT.dom.kv('Type', net.type + (net.security ? ' · ' + net.security : '')),
            CT.dom.kv('Local IP', net.ipv4, { mono: true }),
            CT.dom.kv('Gateway', net.gateway, { mono: true }),
            CT.dom.kv('DNS', (net.dns || []).join(', '), { mono: true }),
            CT.dom.kv('IPv6', net.ipv6 ? net.ipv6 + ' · ' + net.ipv6Mode : 'not configured', { mono: true }),
            CT.dom.kv('Address range', net.range, { mono: true }),
            CT.dom.kv('Active devices', reachable + ' of ' + assets.length)
          ])
        ]) : null,

        h('div.card', [
          h('div.card-head', [icon('activity'), h('h3', 'Recent activity')]),
          timeline(recentActivity())
        ]),

        h('div.btn-grid', [
          h('button.btn.primary', { type: 'button', onClick: () => S.navigate('#/scan') }, [icon('crosshair'), 'New assessment']),
          h('button.btn', { type: 'button', onClick: () => S.navigate('#/reports') }, [icon('report'), 'Reports']),
          h('button.btn', { type: 'button', onClick: () => S.navigate('#/map') }, [icon('map'), 'Network map']),
          h('button.btn', { type: 'button', onClick: () => S.navigate('#/tools') }, [icon('tools'), 'Tools'])
        ])
      ]);
    }
  };

  function dashboardEmpty() {
    return h('div.stack.gap12', [
      CT.dom.empty({
        icon: 'radar',
        title: 'No environment data yet',
        body: 'Define an authorized scope and run an assessment, or explore the fully simulated demo environment.',
        action: { label: 'Start assessment', icon: 'crosshair', onClick: () => S.navigate('#/scan') }
      }),
      h('div.card', [
        h('div.card-head', [icon('layers'), h('h3', 'Explore a demo environment')]),
        h('p.small.dim', 'Loads a complete simulated estate so every screen — findings, reports, comparison, the network map — can be reviewed without touching a real network.'),
        h('div.stack.gap8.mt8', CT.demo.ENVIRONMENTS.map((e) => h('button.profile-card', {
          type: 'button',
          onClick: () => { CT.store.seedDemo(e.id); S.toast('Loaded ' + e.name, 'ok'); S.render(); }
        }, [
          h('span.pico', icon('database')),
          h('span.grow', [h('span.ptitle', e.name), h('span.pdesc', e.desc)])
        ])))
      ])
    ]);
  }

  /* ==========================================================================
     SECURITY SCORE — full derivation
     ======================================================================= */
  CT.ui.routes.score = {
    parent: '#/dashboard', tab: 'dashboard',
    title: () => 'Security score',
    subtitle: () => 'How the number is derived',
    render() {
      const cur = CT.store.currentAssessment();
      if (!cur) return S.emptyNoAssessment('the score');
      const score = CT.store.liveScore();
      const findings = CT.store.findings();

      return h('div.stack.gap12', [
        S.simulatedBanner(cur),
        scoreCard(score, { hideLink: true }),

        h('div.card', [
          h('div.card-head', [icon('sort'), h('h3', 'Score breakdown')]),
          breakdownList(score),
          h('p.tiny.muted.mt12', { style: { 'line-height': '1.55' } }, score.method)
        ]),

        h('div.card', [
          h('div.card-head', [icon('info'), h('h3', 'Dimension detail')]),
          h('div.list', score.breakdown.map((d) => h('div.list-item.static', { style: { display: 'block' } }, [
            h('div.row.gap8', [
              h('span.grow', { style: { 'font-size': '0.89em', 'font-weight': '620' } }, d.label),
              h('span.tag', 'weight ' + Math.round(d.weight * 100) + '%'),
              h('span.mono', { style: { 'font-size': '0.85em', 'font-weight': '650' } }, d.pct + '%')
            ]),
            h('p.tiny.muted.mt4', { style: { margin: '4px 0 0' } }, d.about),
            h('p.tiny.mt4', { style: { margin: '4px 0 0', color: 'var(--text-2)' } }, d.detail),
            h('div.row.gap6.mt6', [
              h('span.tiny.muted', 'Costs'),
              h('span.tiny', { style: { color: d.pointsLost > 5 ? 'var(--sev-high)' : 'var(--text-2)', 'font-weight': '650' } },
                d.pointsLost + ' points'),
              h('span.tiny.muted', 'of the final score'),
              d.findingIds.length ? h('button.btn.sm.quiet', {
                type: 'button', style: { 'margin-left': 'auto' },
                onClick: () => S.navigate('#/findings')
              }, CT.util.plural(d.findingIds.length, 'finding')) : null
            ])
          ])))
        ]),

        h('div.card', [
          h('div.card-head', [icon('alert'), h('h3', 'Largest contributors')]),
          h('div.list', topContributors(findings, score).map((c) => h('div.list-item.static', [
            S.severityPill(c.finding.severity, { short: true }),
            h('span.grow.stack', [
              h('span', { style: { 'font-size': '0.86em' } }, c.finding.title),
              h('span.tiny.muted', c.finding.assetLabel + ' · ' + c.dimension)
            ]),
            h('span.mono.tiny', { style: { color: 'var(--sev-high)' } }, '−' + c.points)
          ])))
        ]),

        h('div.notice', [
          icon('info'),
          h('div.grow', [
            h('strong', 'Deterministic by design'),
            h('span', 'The same inventory and the same findings always produce the same score. Resolving or accepting a finding removes its weight immediately, so the number moves for a reason you can point at.')
          ])
        ])
      ]);
    }
  };

  function topContributors(findings, score) {
    const active = findings.filter((f) => f.status !== 'resolved' && f.status !== 'accepted');
    const dimOf = CT.engines.risk.RULE_DIMENSION;
    const dimMeta = {};
    score.breakdown.forEach((d) => { dimMeta[d.key] = d; });
    return active.map((f) => {
      const key = dimOf[f.ruleId] || 'configuration';
      const d = dimMeta[key];
      const bucketTotal = d ? d.findingIds.length : 1;
      const w = CT.data.SEV_WEIGHT[f.severity] || 0;
      const share = d && d.pointsLost && bucketTotal
        ? (w / Math.max(1, sumWeights(active, dimOf, key))) * d.pointsLost : 0;
      return { finding: f, dimension: d ? d.label : key, points: Math.round(share * 10) / 10 };
    }).filter((c) => c.points > 0).sort((a, b) => b.points - a.points).slice(0, 6);
  }
  function sumWeights(findings, dimOf, key) {
    return findings.reduce((a, f) => a + ((dimOf[f.ruleId] || 'configuration') === key ? (CT.data.SEV_WEIGHT[f.severity] || 0) : 0), 0);
  }

  /* ==========================================================================
     DISCOVER
     ======================================================================= */
  const DISCOVER_FILTERS = [
    { id: 'all', label: 'All' },
    { id: 'servers', label: 'Servers' },
    { id: 'workstations', label: 'Workstations' },
    { id: 'mobile', label: 'Mobile' },
    { id: 'iot', label: 'IoT' },
    { id: 'network', label: 'Network' },
    { id: 'unknown', label: 'Unknown' },
    { id: 'highrisk', label: 'High risk' }
  ];

  let discoverState = { filter: 'all', query: '' };

  CT.ui.routes.discover = {
    tab: 'discover', keepScroll: true,
    title: () => 'Discover',
    subtitle: () => 'Environment and discovered assets',
    render() {
      const cur = CT.store.currentAssessment();
      const net = cur ? cur.network : null;

      return h('div.stack.gap12', [
        S.simulatedBanner(cur),

        h('div.card', [
          h('div.card-head', [icon('wifi'), h('h3', 'Current environment')]),
          net ? h('dl', [
            CT.dom.kv('Network interface', net.interface, { mono: true }),
            CT.dom.kv('Network name', net.name),
            net.ssid ? CT.dom.kv('SSID', net.ssid) : null,
            net.security ? CT.dom.kv('Wi-Fi security', net.security) : null,
            net.band ? CT.dom.kv('Band / channel', net.band) : null,
            net.signal ? CT.dom.kv('Signal', net.signal + ' dBm') : null,
            CT.dom.kv('Local IP', net.localIp, { mono: true }),
            CT.dom.kv('Subnet', net.subnet + '  (' + net.netmask + ')', { mono: true }),
            CT.dom.kv('Gateway', net.gateway, { mono: true }),
            CT.dom.kv('DNS servers', (net.dns || []).join(', '), { mono: true }),
            CT.dom.kv('DHCP server', net.dhcp, { mono: true }),
            CT.dom.kv('IPv4', net.ipv4, { mono: true }),
            CT.dom.kv('IPv6', net.ipv6 || 'not configured', { mono: true }),
            CT.dom.kv('IPv6 mode', net.ipv6Mode || '—'),
            CT.dom.kv('VPN status', h('span.row.gap6', { style: { 'justify-content': 'flex-end' } }, [
              h('span.status-dot.' + (/not/i.test(net.vpn) ? 'off' : 'ok'), { 'aria-hidden': 'true' }), h('span', net.vpn)])),
            CT.dom.kv('Search domain', net.domain, { mono: true }),
            CT.dom.kv('MTU', net.mtu, { mono: true })
          ]) : h('p.small.muted', 'No environment loaded yet.'),
          h('div.mt12', S.capabilityNote('interfaceInfo'))
        ]),

        cur ? discoverAssets(cur) : CT.dom.empty({
          icon: 'radar',
          title: 'No assets yet',
          body: 'Run an authorized discovery scan to populate your environment.',
          action: { label: 'Start discovery', icon: 'crosshair', onClick: () => S.navigate('#/scan') }
        })
      ]);
    }
  };

  function discoverAssets(cur) {
    const findings = CT.store.findings();
    const all = CT.engines.risk.scoreAll(cur.assets, findings);

    const container = h('div.stack.gap10');
    const listBox = h('div.card.flush');
    const countLine = h('div.tiny.muted');

    function matches(entry) {
      const a = entry.asset;
      if (discoverState.filter === 'highrisk') {
        if (entry.risk.level !== 'high' && entry.risk.level !== 'critical') return false;
      } else if (discoverState.filter !== 'all') {
        if (CT.data.DEVICE_GROUP[a.deviceType] !== discoverState.filter) return false;
      }
      const q = discoverState.query.trim().toLowerCase();
      if (!q) return true;
      const hay = [a.hostname, a.ip, a.ipv6, a.mac, a.vendor, a.os, a.deviceType, a.owner]
        .concat((a.services || []).map((s) => s.port + ' ' + s.name + ' ' + (s.product || '')))
        .filter(Boolean).join(' ').toLowerCase();
      return hay.indexOf(q) !== -1;
    }

    const vlist = new CT.dom.VirtualList({
      scrollEl: S.els.view, itemHeight: 62, threshold: 60,
      renderItem: (entry) => S.assetRow(entry.asset, entry.risk)
    });

    function refresh() {
      const filtered = all.filter(matches);
      countLine.textContent = filtered.length === all.length
        ? CT.util.plural(all.length, 'asset')
        : filtered.length + ' of ' + all.length + ' assets';
      CT.dom.clear(listBox);
      if (!filtered.length) {
        listBox.appendChild(CT.dom.empty({
          icon: 'search', title: 'No matching assets',
          body: discoverState.query ? 'Nothing matches "' + discoverState.query + '" in the current filter.'
                                    : 'No assets fall into this category in the current assessment.',
          secondary: { label: 'Clear filters', onClick: () => { discoverState = { filter: 'all', query: '' }; S.render(); } }
        }));
      } else {
        listBox.appendChild(vlist.root);
        vlist.setItems(filtered);
        vlist.attach();
      }
    }

    const search = h('div.search-bar', [
      icon('search'),
      h('input', {
        type: 'search', value: discoverState.query,
        placeholder: 'IP, hostname, MAC, vendor or service',
        'aria-label': 'Search assets by IP, hostname, MAC, vendor or service',
        on: { input: CT.util.debounce(function () { discoverState.query = this.value; refresh(); }, 140) }
      })
    ]);

    const chips = h('div.chips', { role: 'group', 'aria-label': 'Filter assets' },
      DISCOVER_FILTERS.map((f) => {
        const n = all.filter((e) => {
          if (f.id === 'all') return true;
          if (f.id === 'highrisk') return e.risk.level === 'high' || e.risk.level === 'critical';
          return CT.data.DEVICE_GROUP[e.asset.deviceType] === f.id;
        }).length;
        return h('button.chip', {
          type: 'button', 'aria-pressed': discoverState.filter === f.id ? 'true' : 'false',
          onClick: () => { discoverState.filter = f.id; refresh(); updateChips(); }
        }, [h('span', f.label), h('span.n', String(n))]);
      }));

    function updateChips() {
      Array.from(chips.children).forEach((c, i) =>
        c.setAttribute('aria-pressed', DISCOVER_FILTERS[i].id === discoverState.filter ? 'true' : 'false'));
    }

    container.appendChild(CT.dom.sectionLabel('Discovered assets', countLine));
    container.appendChild(search);
    container.appendChild(chips);
    container.appendChild(listBox);
    refresh();
    return container;
  }

  /* ==========================================================================
     MORE
     ======================================================================= */
  const MORE_ITEMS = [
    { route: '#/assets', icon: 'server', label: 'Assets', desc: 'Full inventory with sorting and filters' },
    { route: '#/map', icon: 'map', label: 'Network map', desc: 'Topology view coloured by risk' },
    { route: '#/reports', icon: 'report', label: 'Reports', desc: 'Executive, technical, inventory and findings reports' },
    { route: '#/history', icon: 'clock', label: 'Scan history', desc: 'Previous assessments' },
    { route: '#/compare', icon: 'compare', label: 'Comparison', desc: 'Diff two assessments' },
    { route: '#/tools', icon: 'tools', label: 'Tools', desc: 'CIDR, DNS, TLS, headers, ports, hashing, notes' },
    { route: '#/notifications', icon: 'bell', label: 'Notifications', desc: 'Changes worth knowing about' },
    { route: '#/audit', icon: 'list', label: 'Audit log', desc: 'Everything this app did, in order' },
    { route: '#/settings', icon: 'settings', label: 'Settings', desc: 'Privacy, security, accessibility' },
    { route: '#/about', icon: 'info', label: 'About & scope policy', desc: 'What this tool does and refuses to do' }
  ];

  CT.ui.routes.more = {
    tab: 'more',
    title: () => 'More',
    render() {
      const unread = CT.store.unreadCount();
      return h('div.stack.gap12', [
        h('div.card.flush', h('div.list', MORE_ITEMS.map((m) => h('button.list-item', {
          type: 'button', onClick: () => S.navigate(m.route)
        }, [
          h('span', { style: { color: 'var(--accent)', display: 'flex' } }, icon(m.icon)),
          h('span.grow.stack', [
            h('span', { style: { 'font-size': '0.9em', 'font-weight': '600' } }, m.label),
            h('span.tiny.muted', m.desc)
          ]),
          m.route === '#/notifications' && unread ? h('span.pill.accent', String(unread)) : null,
          icon('chevronRight', { cls: 'chev' })
        ])))),
        h('div.card', [
          h('div.card-head', [icon('database'), h('h3', 'Demo environment')]),
          h('p.small.dim.mb12', 'Replace the current data with a fully simulated estate. Nothing is sent to a network.'),
          h('div.stack.gap8', CT.demo.ENVIRONMENTS.map((e) => h('button.profile-card', {
            type: 'button',
            'aria-pressed': CT.store.state.environmentId === e.id ? 'true' : 'false',
            onClick: () => {
              S.confirm({
                title: 'Load ' + e.name + '?',
                body: 'This replaces the current assessment history with freshly generated demo assessments.',
                confirmLabel: 'Load'
              }).then((ok) => { if (ok) { CT.store.seedDemo(e.id); S.toast('Loaded ' + e.name, 'ok'); S.navigate('#/dashboard'); } });
            }
          }, [
            h('span.pico', icon('layers')),
            h('span.grow', [h('span.ptitle', e.name), h('span.pdesc', e.desc)])
          ])))
        ])
      ]);
    }
  };
})();
