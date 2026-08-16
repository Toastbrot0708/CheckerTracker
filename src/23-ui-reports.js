/* ============================================================================
   MODULE: CT.ui.routes.reports — report generator, history, comparison
   ========================================================================= */
(function () {
  'use strict';
  const h = CT.dom.h, icon = CT.dom.icon, S = CT.ui.shell;

  /* ==========================================================================
     REPORTS INDEX
     ======================================================================= */
  CT.ui.routes.reports = {
    parent: '#/more', tab: 'more',
    title: () => 'Reports',
    subtitle: () => 'Generate and export',
    render() {
      const cur = CT.store.currentAssessment();
      if (!cur) return S.emptyNoAssessment('reports');
      const preset = CT.ui.reportPreset;
      CT.ui.reportPreset = null;

      return h('div.stack.gap12', [
        S.simulatedBanner(cur),
        h('div.card', [
          h('div.card-head', [icon('clock'), h('h3', 'Source assessment')]),
          h('dl', [
            CT.dom.kv('Assessment', '#' + String(cur.number).padStart(3, '0')),
            CT.dom.kv('Completed', CT.util.fmtDateTime(cur.endedAt)),
            CT.dom.kv('Scope', cur.scopeLabel, { mono: true }),
            CT.dom.kv('Assets / findings', cur.stats.hosts + ' / ' + cur.stats.findings),
            CT.dom.kv('Data origin', cur.simulated ? h('span.demo-chip', 'Simulated') : cur.imported ? 'Imported' : 'Observed')
          ]),
          h('button.btn.sm.ghost.mt12', { type: 'button', onClick: () => S.navigate('#/history') },
            [icon('clock'), 'Use a different assessment'])
        ]),
        CT.dom.sectionLabel('Report types'),
        h('div', CT.engines.report.TYPES.map((t) => h('button.profile-card', {
          type: 'button',
          'aria-pressed': preset === t.id ? 'true' : 'false',
          onClick: () => S.navigate('#/report/' + t.id)
        }, [
          h('span.pico', icon(t.icon)),
          h('span.grow', [
            h('span.ptitle', t.name),
            h('span.pdesc', t.desc),
            h('span.pmeta', t.sections.length + ' sections')
          ]),
          icon('chevronRight', { cls: 'chev' })
        ]))),
        h('div.card', [
          h('div.card-head', [icon('download'), h('h3', 'Quick export')]),
          h('p.small.dim.mb12', 'Raw data exports of the current assessment.'),
          h('div.btn-grid', [
            h('button.btn', { type: 'button', onClick: () => exportJSON(cur, 'technical') }, [icon('copy'), 'JSON']),
            h('button.btn', { type: 'button', onClick: () => exportCSV(cur, 'assets') }, [icon('database'), 'Assets CSV']),
            h('button.btn', { type: 'button', onClick: () => exportCSV(cur, 'findings') }, [icon('alert'), 'Findings CSV']),
            h('button.btn', { type: 'button', onClick: () => S.navigate('#/report/technical') }, [icon('report'), 'Full report'])
          ])
        ])
      ]);
    }
  };

  function withLiveFindings(assessment) {
    return Object.assign({}, assessment, { findings: CT.store.applyFindingState(assessment.findings) });
  }
  function exportJSON(assessment, type) {
    const model = CT.engines.report.build(type, withLiveFindings(assessment));
    S.guardedExport({
      filename: 'checkertracker-' + String(assessment.number).padStart(3, '0') + '-' + type + '.json',
      mime: 'application/json', title: 'Export JSON',
      summary: model.stats.assets + ' assets, ' + model.stats.findings + ' findings',
      content: CT.engines.report.toJSON(model)
    });
    CT.store.audit('report.generate', 'JSON export of ' + model.typeName);
    CT.store.commit();
  }
  function exportCSV(assessment, which) {
    const model = CT.engines.report.build('technical', withLiveFindings(assessment));
    S.guardedExport({
      filename: 'checkertracker-' + String(assessment.number).padStart(3, '0') + '-' + which + '.csv',
      mime: 'text/csv', title: 'Export ' + which + ' CSV',
      summary: which === 'assets' ? model.stats.assets + ' rows' : model.stats.findings + ' rows',
      content: CT.engines.report.toCSV(model, which)
    });
    CT.store.audit('report.generate', 'CSV export (' + which + ')');
    CT.store.commit();
  }

  /* ==========================================================================
     REPORT DOCUMENT
     ======================================================================= */
  CT.ui.routes.report = {
    parent: '#/reports', tab: 'more',
    title: (p) => { const t = CT.engines.report.TYPES.find((x) => x.id === p[0]); return t ? t.name : 'Report'; },
    subtitle: () => { const c = CT.store.currentAssessment(); return c ? '#' + String(c.number).padStart(3, '0') : null; },
    render(params) {
      const cur = CT.store.currentAssessment();
      if (!cur) return S.emptyNoAssessment('reports');
      const model = CT.engines.report.build(params[0] || 'technical', withLiveFindings(cur));
      const has = (s) => model.sections.indexOf(s) !== -1;

      return h('div.stack.gap12', [
        h('div.btn-grid.no-print', [
          h('button.btn.primary', { type: 'button', onClick: () => printReport() }, [icon('report'), 'PDF / Print']),
          h('button.btn', { type: 'button', onClick: () => exportJSON(cur, model.type) }, [icon('copy'), 'JSON']),
          h('button.btn', { type: 'button', onClick: () => exportCSV(cur, 'findings') }, [icon('alert'), 'Findings CSV']),
          h('button.btn', { type: 'button', onClick: () => exportCSV(cur, 'assets') }, [icon('database'), 'Assets CSV'])
        ]),

        h('div.report-page.stack.gap12', [
          model.simulated ? h('div.demo-banner', [icon('alert'), h('div.grow', [
            h('strong', 'SIMULATED ASSESSMENT'),
            ' — this report describes the "' + model.assessment.environment + '" demo environment. No real system was assessed.'
          ])]) : null,

          h('div.card', [
            h('div.row.gap12', [
              h('span', { style: { color: 'var(--accent)', display: 'flex' } }, CT.icons.logo(34)),
              h('span.grow', [
                h('div', { style: { 'font-size': '1.1em', 'font-weight': '700' } }, model.typeName),
                h('div.tiny.muted', 'CheckerTracker · Assessment #' + String(model.assessment.number).padStart(3, '0'))
              ])
            ]),
            h('dl.mt12', [
              CT.dom.kv('Generated', CT.util.fmtDateTime(model.generatedAt)),
              CT.dom.kv('Scope', model.assessment.scope, { mono: true }),
              CT.dom.kv('Profile', model.assessment.profile),
              CT.dom.kv('Assessment window', CT.util.fmtDateTime(model.assessment.startedAt) + ' → ' +
                CT.util.fmtDateTime(model.assessment.endedAt)),
              CT.dom.kv('Duration', CT.util.fmtClock(model.assessment.durationMs), { mono: true }),
              CT.dom.kv('Data origin', model.simulated ? 'SIMULATED (demo environment)' : model.assessment.mode === 'imported' ? 'Imported dataset' : 'Observed in scope')
            ])
          ]),

          has('summary') ? section('Executive summary', executiveSummary(model)) : null,
          has('score') ? section('Security score', scoreSection(model)) : null,
          has('topFindings') ? section('Findings requiring attention', topFindingsSection(model)) : null,
          has('scope') ? section('Scope', scopeSection(model)) : null,
          has('methodology') ? section('Methodology', methodologySection(model)) : null,
          has('networkOverview') ? section('Network overview', networkSection(model)) : null,
          has('assets') ? section('Assets (' + model.stats.assets + ')', assetsSection(model)) : null,
          has('findings') ? section('Findings (' + model.stats.findings + ')', findingsSection(model)) : null,
          has('recommendations') ? section('Recommendations', recommendationsSection(model)) : null,
          has('timeline') ? section('Scan timeline', timelineSection(model)) : null,
          has('disclaimer') ? h('div.card', [
            h('div.section-label', 'Disclaimer'),
            h('p.small.dim', model.disclaimer),
            h('p.tiny.muted.mt8', { style: { margin: '8px 0 0' } },
              'CheckerTracker performs read-only observation. No authentication was attempted, no vulnerability was exercised and no configuration was modified on any system. Findings describe observed configuration state and require manual verification before remediation.')
          ]) : null
        ])
      ]);
    }
  };

  function printReport() {
    try {
      window.print();
      CT.store.audit('report.generate', 'Report sent to the print/PDF dialog');
      CT.store.commit();
    } catch (e) {
      S.toast('Printing is blocked in this context — use JSON or CSV export instead', 'warn', 4000);
    }
  }

  function section(title, content) {
    return h('div.card', [h('div.section-label', [h('span', title), h('span.line')]), content]);
  }

  function executiveSummary(m) {
    const s = m.score;
    const c = s.counts || CT.engines.risk.countBySeverity(m.findings);
    const worst = CT.data.SEVERITIES.find((sv) => c[sv] > 0);
    return h('div.stack.gap10', [
      h('p.small', { style: { color: 'var(--text-2)', 'line-height': '1.6' } },
        'The environment scored ' + s.score + ' out of 100 (' + s.grade.label.toLowerCase() + '). ' +
        CT.util.plural(m.stats.assets, 'device') + ' responded inside the authorized scope, exposing ' +
        CT.util.plural(m.stats.services, 'network service') + '. ' +
        (m.findings.length
          ? CT.util.plural(m.findings.length, 'finding') + ' were recorded' +
            (worst ? ', the most severe rated ' + CT.data.SEV_LABEL[worst].toLowerCase() + '. ' : '. ') +
            (s.attention ? CT.util.plural(s.attention, 'finding') + ' at critical or high severity require attention before the next review cycle.' : 'None are rated critical or high.')
          : 'No findings were recorded.')),
      m.stats.unknownAssets
        ? h('p.small', { style: { color: 'var(--text-2)', 'line-height': '1.6' } },
          CT.util.plural(m.stats.unknownAssets, 'device') + ' responded that are not present in the expected inventory. Establishing ownership for these is the highest-value inventory action.')
        : null,
      h('div.metric-grid.c2', [
        S.metric(s.score + '/100', 'Security score'),
        S.metric(m.stats.assets, 'Assets in scope')
      ]),
      m.findings.length ? S.severityBar(c, m.findings.length) : null
    ]);
  }

  function scoreSection(m) {
    return h('div.stack.gap10', [
      h('div', m.score.breakdown.map((d) => h('div.breakdown-row', [
        h('span.name', d.label),
        CT.dom.bar(d.pct, d.pct >= 85 ? 'ok' : d.pct >= 65 ? 'warn' : d.pct >= 40 ? 'bad' : 'crit'),
        h('span.pct', d.pct + '%')
      ]))),
      h('div.tbl-wrap', h('table.tbl', [
        h('thead', h('tr', [h('th', 'Dimension'), h('th', 'Score'), h('th', 'Weight'), h('th', 'Points lost')])),
        h('tbody', m.score.breakdown.map((d) => h('tr', [
          h('td', d.label), h('td.num', d.pct + '%'),
          h('td.num', Math.round(d.weight * 100) + '%'), h('td.num', '−' + d.pointsLost)
        ])))
      ])),
      h('p.tiny.muted', m.score.method)
    ]);
  }

  function topFindingsSection(m) {
    const top = m.findings.filter((f) => f.severity === 'critical' || f.severity === 'high').slice(0, 10);
    if (!top.length) return h('p.small.dim', 'No critical or high severity findings were recorded.');
    return h('div.list', top.map((f) => h('div.list-item.static', { style: { display: 'block' } }, [
      h('div.row.gap6', [S.severityPill(f.severity, { short: true }), h('span.tag', f.ruleId)]),
      h('div.small.mt4', { style: { 'font-weight': '600' } }, f.title),
      h('div.tiny.muted.mt4', f.assetLabel + (f.service ? ' · ' + f.service : ''))
    ])));
  }

  function scopeSection(m) {
    return h('div.stack.gap10', [
      h('dl', [
        CT.dom.kv('Authorized scope', m.assessment.scope, { mono: true }),
        CT.dom.kv('Environment', m.assessment.environment),
        CT.dom.kv('Confirmed at', m.assessment.authorizedBy ? CT.util.fmtDateTime(m.assessment.authorizedBy.grantedAt) : '—'),
        CT.dom.kv('Window expires', m.assessment.authorizedBy ? CT.util.fmtDateTime(m.assessment.authorizedBy.expiresAt) : '—'),
        CT.dom.kv('Assets responding', String(m.stats.assets)),
        CT.dom.kv('Services observed', String(m.stats.services))
      ]),
      h('p.tiny.muted', 'Only addresses inside the declared scope were included. Nothing outside it was contacted.')
    ]);
  }

  function methodologySection(m) {
    return h('div.stack.gap10', [
      h('dl', [CT.dom.kv('Profile', m.methodology.profile)]),
      h('p.small', { style: { color: 'var(--text-2)' } }, m.methodology.description),
      h('div', [
        h('div.section-label.mt8', 'Checks performed'),
        h('ul', { style: { margin: 0, 'padding-left': '20px', 'font-size': '0.84em', color: 'var(--text-2)', 'line-height': '1.7' } },
          m.methodology.checks.map((c) => h('li', c)))
      ]),
      h('div', [
        h('div.section-label.mt8', 'Explicitly excluded'),
        h('ul', { style: { margin: 0, 'padding-left': '20px', 'font-size': '0.84em', color: 'var(--text-2)', 'line-height': '1.7' } },
          m.methodology.excluded.map((c) => h('li', c)))
      ])
    ]);
  }

  function networkSection(m) {
    const byType = CT.util.groupBy(m.assets, (a) => a.deviceType);
    const byCat = new Map();
    m.assets.forEach((a) => (a.services || []).forEach((s) => {
      const ref = CT.data.portInfo(s.port);
      const k = ref ? ref.category : 'Other';
      byCat.set(k, (byCat.get(k) || 0) + 1);
    }));
    return h('div.stack.gap12', [
      h('div', [
        h('div.section-label', 'Device distribution'),
        h('div.tbl-wrap', h('table.tbl', [
          h('thead', h('tr', [h('th', 'Device type'), h('th', 'Count'), h('th', 'Share')])),
          h('tbody', Array.from(byType.entries()).sort((a, b) => b[1].length - a[1].length).map(([t, list]) => h('tr', [
            h('td', t), h('td.num', String(list.length)),
            h('td.num', Math.round(list.length / m.assets.length * 100) + '%')
          ])))
        ]))
      ]),
      h('div', [
        h('div.section-label', 'Service exposure profile'),
        h('div.tbl-wrap', h('table.tbl', [
          h('thead', h('tr', [h('th', 'Category'), h('th', 'Services')])),
          h('tbody', Array.from(byCat.entries()).sort((a, b) => b[1] - a[1]).map(([c, n]) => h('tr', [
            h('td', c), h('td.num', String(n))
          ])))
        ]))
      ])
    ]);
  }

  function assetsSection(m) {
    return h('div.tbl-wrap', h('table.tbl', [
      h('thead', h('tr', [h('th', 'Host'), h('th', 'Address'), h('th', 'Type'), h('th', 'Svc'), h('th', 'Inv')])),
      h('tbody', m.assets.slice(0, 600).map((a) => h('tr', [
        h('td', a.hostname || h('span.muted', 'unnamed')),
        h('td', h('span.mono.tiny', a.ip)),
        h('td', h('span.tiny', a.deviceType)),
        h('td.num', String((a.services || []).length)),
        h('td', a.inInventory === false ? h('span.pill.medium', 'no') : h('span.tiny.muted', 'yes'))
      ])))
    ]));
  }

  function findingsSection(m) {
    if (!m.findings.length) return h('p.small.dim', 'No findings were recorded.');
    return h('div.stack.gap12', CT.data.SEVERITIES.filter((s) => m.bySeverity[s].length).map((s) =>
      h('div', [
        h('div.row.gap8.mb8', [S.severityPill(s), h('span.tiny.muted', CT.util.plural(m.bySeverity[s].length, 'finding'))]),
        h('div.list', m.bySeverity[s].map((f) => {
          const rt = CT.data.rule(f.ruleId);
          return h('div.list-item.static', { style: { display: 'block', padding: '10px 0' } }, [
            h('div.row.gap6.wrap', [h('span.tag', f.ruleId), h('span.tag', f.assetLabel),
              (f.status && f.status !== 'open') ? h('span.pill.neutral', f.status) : null]),
            h('div.small.mt4', { style: { 'font-weight': '620' } }, f.title),
            f.detail ? h('div.tiny.muted.mt4', f.detail) : null,
            h('div.tiny.mt6', { style: { color: 'var(--text-2)' } }, rt.description),
            (f.evidence || []).length ? h('div.mt6', (f.evidence || []).slice(0, 4).map((e) =>
              h('div.evidence', [h('div.e-label', e.label), h('div.e-value', e.value)]))) : null,
            (rt.remediation || []).length ? h('div.mt6', [
              h('div.tiny.muted', 'Remediation'),
              h('ul', { style: { margin: '4px 0 0', 'padding-left': '18px', 'font-size': '0.78em', color: 'var(--text-2)', 'line-height': '1.6' } },
                rt.remediation.map((r) => h('li', r)))
            ]) : null
          ]);
        }))
      ])));
  }

  function recommendationsSection(m) {
    if (!m.recommendations.length) return h('p.small.dim', 'No remediation actions were derived.');
    return h('div.list', m.recommendations.slice(0, 20).map((r, i) => h('div.list-item.static', [
      h('span.mono.tiny.muted', { style: { flex: '0 0 22px' } }, String(i + 1).padStart(2, '0')),
      h('span.grow.stack', [
        h('span.small', r.text),
        h('span.tiny.muted', 'Addresses ' + CT.util.plural(r.count, 'finding'))
      ]),
      S.severityPill(r.worst, { short: true })
    ])));
  }

  function timelineSection(m) {
    return h('dl', [
      CT.dom.kv('Started', CT.util.fmtDateTime(m.assessment.startedAt)),
      CT.dom.kv('Completed', CT.util.fmtDateTime(m.assessment.endedAt)),
      CT.dom.kv('Duration', CT.util.fmtClock(m.assessment.durationMs), { mono: true }),
      CT.dom.kv('Report generated', CT.util.fmtDateTime(m.generatedAt)),
      CT.dom.kv('Profile', m.assessment.profile)
    ]);
  }

  /* ==========================================================================
     HISTORY
     ======================================================================= */
  CT.ui.routes.history = {
    parent: '#/more', tab: 'more',
    title: () => 'Scan history',
    subtitle: () => CT.util.plural(CT.store.state.assessments.length, 'assessment'),
    render() {
      const list = CT.store.state.assessments.slice().reverse();
      if (!list.length) return S.emptyNoAssessment('history');
      const currentId = (CT.store.currentAssessment() || {}).id;

      return h('div.stack.gap12', [
        scoreTrend(CT.store.state.assessments),
        h('div.card.flush', h('div.list', list.map((a) => {
          const counts = CT.engines.risk.countBySeverity(a.findings);
          const worst = CT.data.SEVERITIES.find((s) => counts[s] > 0) || 'informational';
          return h('button.list-item', {
            type: 'button',
            onClick: () => assessmentSheet(a),
            'aria-label': 'Assessment ' + a.number + ', ' + CT.util.fmtDate(a.endedAt)
          }, [
            h('span.grow.stack', { style: { 'min-width': '0' } }, [
              h('span.row.gap6', [
                h('span', { style: { 'font-weight': '650', 'font-size': '0.92em' } }, 'Assessment #' + String(a.number).padStart(3, '0')),
                a.id === currentId ? h('span.pill.accent', 'current') : null,
                a.simulated ? h('span.demo-chip', 'sim') : null
              ]),
              h('span.tiny.muted.mt4', CT.util.fmtDate(a.endedAt) + ' · ' + a.profileName),
              h('span.tiny.muted.mono.trunc', a.scopeLabel),
              h('span.row.gap8.mt4', [
                h('span.tiny.muted', CT.util.fmtClock(a.durationMs)),
                h('span.tiny.muted', a.stats.hosts + ' assets'),
                h('span.tiny.muted', a.stats.findings + ' findings')
              ])
            ]),
            h('span.stack', { style: { 'align-items': 'flex-end', flex: '0 0 auto' } }, [
              h('span', { style: { 'font-weight': '700', 'font-size': '0.95em' } }, String(a.score.score)),
              h('span.tiny', { style: { color: 'var(--sev-' + (worst === 'informational' ? 'info' : worst) + ')' } },
                CT.data.SEV_LABEL[worst])
            ]),
            icon('chevronRight', { cls: 'chev' })
          ]);
        }))),
        h('button.btn.block', { type: 'button', onClick: () => S.navigate('#/compare') }, [icon('compare'), 'Compare two assessments'])
      ]);
    }
  };

  /**
   * Score trajectory across stored assessments. Fixed 0–100 scale so the
   * shape is comparable rather than auto-fitted to whatever range happens to
   * be present. The endpoint carries the current grade colour; the line and
   * fill stay on the accent so semantic colour keeps its meaning.
   */
  const GRADE_COLOR = { ok: 'var(--ok)', warn: 'var(--sev-medium)', bad: 'var(--sev-high)', crit: 'var(--sev-critical)' };

  function scoreTrend(all) {
    const pts = all.slice(-12);
    if (pts.length < 2) return null;

    const W = 300, H = 68, PAD_X = 5, PAD_Y = 8;
    const px = (i) => PAD_X + (i / (pts.length - 1)) * (W - 2 * PAD_X);
    const py = (v) => H - PAD_Y - (CT.util.clamp(v, 0, 100) / 100) * (H - 2 * PAD_Y);

    const line = pts.map((a, i) => (i ? 'L' : 'M') + px(i).toFixed(1) + ' ' + py(a.score.score).toFixed(1)).join(' ');
    const area = line + ' L' + px(pts.length - 1).toFixed(1) + ' ' + (H - PAD_Y) + ' L' + px(0).toFixed(1) + ' ' + (H - PAD_Y) + ' Z';

    const last = pts[pts.length - 1];
    const first = pts[0];
    const delta = last.score.score - first.score.score;
    const endColor = GRADE_COLOR[last.score.grade.kind];

    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
    svg.setAttribute('preserveAspectRatio', 'none');
    svg.setAttribute('width', '100%');
    svg.setAttribute('height', String(H));
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', 'Security score across the last ' + pts.length +
      ' assessments: ' + pts.map((a) => a.score.score).join(', ') + '. Currently ' +
      last.score.score + ' out of 100, ' + (delta === 0 ? 'unchanged' : delta > 0 ? 'up ' + delta : 'down ' + Math.abs(delta)) +
      ' since assessment ' + first.number + '.');
    svg.innerHTML =
      // Reference lines at 50 and 80 give the shape a scale to read against.
      '<line x1="0" y1="' + py(80) + '" x2="' + W + '" y2="' + py(80) + '" stroke="var(--border)" stroke-width="1" stroke-dasharray="3 4" vector-effect="non-scaling-stroke"/>' +
      '<line x1="0" y1="' + py(50) + '" x2="' + W + '" y2="' + py(50) + '" stroke="var(--border)" stroke-width="1" stroke-dasharray="3 4" vector-effect="non-scaling-stroke"/>' +
      '<path d="' + area + '" fill="var(--accent)" fill-opacity="0.12"/>' +
      '<path d="' + line + '" fill="none" stroke="var(--accent)" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke"/>' +
      '<circle cx="' + px(pts.length - 1).toFixed(1) + '" cy="' + py(last.score.score).toFixed(1) +
        '" r="3.5" fill="' + endColor + '" stroke="var(--card)" stroke-width="2" vector-effect="non-scaling-stroke"/>';

    return h('div.card', [
      h('div.card-head', [
        icon('trendUp'), h('h3', 'Score trajectory'),
        delta !== 0
          ? h('span.pill.' + (delta > 0 ? 'ok' : 'high'), [
            h('span.glyph', { 'aria-hidden': 'true' }, delta > 0 ? '▲' : '▼'),
            h('span', (delta > 0 ? '+' : '') + delta)
          ])
          : h('span.pill.neutral', 'flat')
      ]),
      svg,
      h('div.row.gap8.mt6', [
        h('span.tiny.muted', '#' + String(first.number).padStart(3, '0')),
        h('span.grow.tiny.muted.center', 'dashed guides at 50 and 80'),
        h('span.tiny.muted', '#' + String(last.number).padStart(3, '0') + ' · ' + last.score.score + '/100')
      ])
    ]);
  }

  function assessmentSheet(a) {
    const counts = CT.engines.risk.countBySeverity(a.findings);
    const isCurrent = (CT.store.currentAssessment() || {}).id === a.id;
    const s = S.sheet({
      title: 'Assessment #' + String(a.number).padStart(3, '0'),
      body: h('div.stack.gap12', [
        a.simulated ? h('div.demo-banner', [icon('alert'), h('div.grow', [h('strong', 'SIMULATED'), ' — demo environment data.'])]) : null,
        h('dl', [
          CT.dom.kv('Date', CT.util.fmtDateTime(a.endedAt)),
          CT.dom.kv('Scope', a.scopeLabel, { mono: true }),
          CT.dom.kv('Profile', a.profileName),
          CT.dom.kv('Duration', CT.util.fmtClock(a.durationMs), { mono: true }),
          CT.dom.kv('Assets', String(a.stats.hosts)),
          CT.dom.kv('Services', String(a.stats.services)),
          CT.dom.kv('Findings', String(a.stats.findings)),
          CT.dom.kv('Security score', a.score.score + ' / 100 · ' + a.score.grade.label)
        ]),
        a.findings.length ? S.severityBar(counts, a.findings.length) : null
      ]),
      footer: h('div.stack.gap8', [
        h('div.btn-row', [
          h('button.btn.ghost', { type: 'button', onClick: () => { s.close(); S.navigate('#/compare'); } }, [icon('compare'), 'Compare']),
          isCurrent
            ? h('button.btn', { type: 'button', disabled: true }, 'Currently open')
            : h('button.btn.primary', {
              type: 'button',
              onClick: () => { CT.store.setCurrentAssessment(a.id); s.close(); S.toast('Assessment #' + a.number + ' loaded', 'ok'); S.navigate('#/dashboard'); }
            }, [icon('check'), 'Open'])
        ]),
        h('button.btn.ghost.block', { type: 'button', onClick: () => { s.close(); exportJSON(a, 'technical'); } }, [icon('download'), 'Export JSON'])
      ])
    });
  }

  /* ==========================================================================
     COMPARISON
     ======================================================================= */
  let cmp = { a: null, b: null };

  CT.ui.routes.compare = {
    parent: '#/more', tab: 'more',
    title: () => 'Comparison',
    subtitle: () => 'Diff two assessments',
    render() {
      const list = CT.store.state.assessments;
      if (list.length < 2) {
        return CT.dom.empty({
          icon: 'compare', title: 'Two assessments required',
          body: 'Comparison needs a baseline and a current assessment. Run another scan, or load a demo environment which seeds both.',
          action: { label: 'Open Scan Center', icon: 'crosshair', onClick: () => S.navigate('#/scan') },
          secondary: { label: 'Load demo environment', onClick: () => { CT.store.seedDemo(CT.store.state.environmentId); S.render(); } }
        });
      }
      const cur = CT.store.currentAssessment();
      const idx = list.indexOf(cur);
      if (!cmp.a || !list.some((x) => x.id === cmp.a)) cmp.a = (list[idx - 1] || list[list.length - 2]).id;
      if (!cmp.b || !list.some((x) => x.id === cmp.b)) cmp.b = cur.id;

      const A = list.find((x) => x.id === cmp.a);
      const B = list.find((x) => x.id === cmp.b);
      const d = CT.engines.assetdb.diffSnapshots(A.assets, B.assets);
      const fd = CT.engines.assetdb.diffFindings(A.findings, B.findings);
      const scoreDelta = B.score.score - A.score.score;
      // Services that arrived with a brand-new asset are already represented
      // by the "new assets" figure; the headline counts drift on hosts that
      // existed in both snapshots.
      const driftServices = d.newServices.filter((s) => !s.viaNewAsset);
      const newAssetServices = d.newServices.filter((s) => s.viaNewAsset);

      const label = (x) => '#' + String(x.number).padStart(3, '0') + ' · ' + CT.util.fmtDate(x.endedAt);

      return h('div.stack.gap12', [
        h('div.card', [
          h('div.card-head', [icon('compare'), h('h3', 'Select assessments')]),
          h('label.field', [
            h('span.lbl', 'Baseline'),
            h('select', { 'aria-label': 'Baseline assessment', on: { change: function () { cmp.a = this.value; S.render(); } } },
              list.map((x) => h('option', { value: x.id, selected: cmp.a === x.id ? true : null }, label(x))))
          ]),
          h('label.field', { style: { margin: 0 } }, [
            h('span.lbl', 'Compared with'),
            h('select', { 'aria-label': 'Comparison assessment', on: { change: function () { cmp.b = this.value; S.render(); } } },
              list.map((x) => h('option', { value: x.id, selected: cmp.b === x.id ? true : null }, label(x))))
          ])
        ]),

        h('div.card', [
          h('div.card-head', [icon('trendUp'), h('h3', 'Security score')]),
          h('div.row.gap16', [
            h('div.stack.grow', [
              h('div.tiny.muted', 'Previous'),
              h('div', { style: { 'font-size': '1.8em', 'font-weight': '700', 'line-height': '1.1' } }, String(A.score.score)),
              h('div.tiny.muted', A.score.grade.label)
            ]),
            h('div', { style: { color: 'var(--text-3)', display: 'flex' } }, icon('arrowRight')),
            h('div.stack.grow', [
              h('div.tiny.muted', 'Current'),
              h('div', {
                style: { 'font-size': '1.8em', 'font-weight': '700', 'line-height': '1.1',
                         color: scoreDelta > 0 ? 'var(--ok)' : scoreDelta < 0 ? 'var(--sev-high)' : 'var(--text)' }
              }, String(B.score.score)),
              h('div.tiny.muted', B.score.grade.label)
            ]),
            h('div', scoreDelta !== 0
              ? h('span.pill.' + (scoreDelta > 0 ? 'ok' : 'high'), [
                h('span.glyph', { 'aria-hidden': 'true' }, scoreDelta > 0 ? '▲' : '▼'),
                h('span', (scoreDelta > 0 ? '+' : '') + scoreDelta)
              ])
              : h('span.pill.neutral', 'no change'))
          ]),
          h('div.mt12', A.score.breakdown.map((dim, i) => {
            const other = B.score.breakdown[i];
            const dd = other.pct - dim.pct;
            return h('div.breakdown-row', [
              h('span.name', dim.label),
              CT.dom.bar(other.pct, other.pct >= 85 ? 'ok' : other.pct >= 65 ? 'warn' : 'bad'),
              h('span.pct', { style: { color: dd > 0 ? 'var(--ok)' : dd < 0 ? 'var(--sev-high)' : 'var(--text-3)' } },
                (dd > 0 ? '+' : '') + dd)
            ]);
          }))
        ]),

        h('div.metric-grid.c2', [
          deltaMetric(d.added.length, 'New assets', 'bad'),
          deltaMetric(-d.removed.length, 'Removed assets', 'neutral')
        ]),
        h('div.metric-grid.c2', [
          deltaMetric(driftServices.length, 'New services', 'bad'),
          deltaMetric(-d.removedServices.length, 'Closed services', 'good')
        ]),
        newAssetServices.length
          ? h('p.tiny.muted', { style: { margin: '-2px 2px 0' } },
            'Plus ' + CT.util.plural(newAssetServices.length, 'service') + ' arriving with the new assets above.')
          : null,
        h('div.metric-grid.c2', [
          deltaMetric(fd.added.length, 'New findings', 'bad'),
          deltaMetric(-fd.resolved.length, 'Resolved findings', 'good')
        ]),

        diffGroup('New assets', d.added.map((a) => ({
          primary: (a.hostname || 'unnamed') + ' · ' + a.ip,
          secondary: a.deviceType + (a.vendor ? ' · ' + a.vendor : '') + (a.inInventory === false ? ' · not in inventory' : ''),
          kind: a.inInventory === false ? 'bad' : 'warn',
          onClick: () => S.navigate('#/asset/' + a.id)
        })), 'No new assets appeared.'),

        diffGroup('Removed assets', d.removed.map((a) => ({
          primary: (a.hostname || 'unnamed') + ' · ' + a.ip,
          secondary: a.deviceType + ' — no longer responding',
          kind: 'ok'
        })), 'No assets disappeared.'),

        diffGroup('New services on existing assets', driftServices.map((s) => ({
          primary: s.service.port + '/' + s.service.proto + ' ' + s.service.name,
          secondary: (s.asset.hostname || s.asset.ip) + ' — not present in the baseline',
          kind: 'warn',
          onClick: () => S.navigate('#/asset/' + s.asset.id)
        })), 'No service drift on assets present in both snapshots.'),

        diffGroup('Closed services', d.removedServices.map((s) => ({
          primary: s.service.port + '/' + s.service.proto + ' ' + s.service.name,
          secondary: (s.asset.hostname || s.asset.ip) + ' — no longer responding',
          kind: 'ok',
          onClick: () => S.navigate('#/asset/' + s.asset.id)
        })), 'No services were closed.'),

        diffGroup('New findings', fd.added.map((f) => ({
          primary: f.title,
          secondary: f.assetLabel + ' · ' + CT.data.SEV_LABEL[f.severity],
          kind: f.severity === 'critical' || f.severity === 'high' ? 'bad' : 'warn',
          onClick: () => S.navigate('#/finding/' + encodeURIComponent(f.id))
        })), 'No new findings.'),

        diffGroup('Resolved findings', fd.resolved.map((f) => ({
          primary: f.title,
          secondary: f.assetLabel + ' · was ' + CT.data.SEV_LABEL[f.severity],
          kind: 'ok'
        })), 'No findings were resolved.'),

        h('div.notice', [icon('info'), h('div.grow', [
          h('strong', 'Computed, not stored'),
          h('span', 'Both snapshots are diffed on demand, so the deltas always reflect the two assessments you selected.')
        ])])
      ]);
    }
  };

  function deltaMetric(n, label, tone) {
    const positive = n > 0;
    const color = n === 0 ? 'var(--text-2)'
      : tone === 'good' ? 'var(--ok)'
        : tone === 'bad' ? (positive ? 'var(--sev-high)' : 'var(--ok)')
          : 'var(--text-2)';
    return h('div.metric', [
      h('div.v', { style: { color } }, (n > 0 ? '+' : '') + n),
      h('div.l', label)
    ]);
  }

  function diffGroup(title, items, emptyText) {
    return h('div.card', [
      h('div.card-head', [h('h3', title), h('span.tag', String(items.length))]),
      items.length
        ? h('div.list', items.slice(0, 40).map((i) => {
          const inner = [
            h('span.status-dot.' + (i.kind === 'ok' ? 'ok' : i.kind === 'bad' ? 'critical' : 'medium'), { 'aria-hidden': 'true' }),
            h('span.grow.stack', { style: { 'min-width': '0' } }, [
              h('span.small.trunc', i.primary),
              h('span.tiny.muted.trunc', i.secondary)
            ])
          ];
          return i.onClick
            ? h('button.list-item', { type: 'button', onClick: i.onClick }, inner.concat([icon('chevronRight', { cls: 'chev' })]))
            : h('div.list-item.static', inner);
        }))
        : h('p.small.muted', emptyText)
    ]);
  }
})();
