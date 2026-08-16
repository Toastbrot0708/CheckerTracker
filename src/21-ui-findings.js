/* ============================================================================
   MODULE: CT.ui.routes.findings — findings list and finding detail
   ========================================================================= */
(function () {
  'use strict';
  const h = CT.dom.h, icon = CT.dom.icon, S = CT.ui.shell;

  let fs = { severity: 'all', status: 'open', query: '', sort: 'severity' };

  const STATUS_LABEL = {
    open: 'Open', in_progress: 'In progress', resolved: 'Resolved', accepted: 'Risk accepted'
  };

  /* ==========================================================================
     LIST
     ======================================================================= */
  CT.ui.routes.findings = {
    tab: 'findings', keepScroll: true,
    title: () => 'Findings',
    subtitle: () => {
      const n = CT.store.activeFindings().length;
      return n ? CT.util.plural(n, 'open finding') : 'No open findings';
    },
    render(params) {
      const cur = CT.store.currentAssessment();
      if (!cur) return S.emptyNoAssessment('findings');
      if (params[0] && CT.data.SEVERITIES.indexOf(params[0]) !== -1) fs.severity = params[0];

      const all = CT.store.findings();
      const container = h('div.stack.gap10');
      const listBox = h('div.card.flush');
      const countLine = h('div.tiny.muted');

      function matches(f) {
        if (fs.severity !== 'all' && f.severity !== fs.severity) return false;
        const st = f.status || 'open';
        if (fs.status === 'open' && (st === 'resolved' || st === 'accepted')) return false;
        if (fs.status === 'resolved' && st !== 'resolved') return false;
        if (fs.status === 'accepted' && st !== 'accepted') return false;
        const q = fs.query.trim().toLowerCase();
        if (!q) return true;
        return [f.title, f.assetLabel, f.assetIp, f.ruleId, f.service, f.category, f.detail]
          .filter(Boolean).join(' ').toLowerCase().indexOf(q) !== -1;
      }

      function sortFn(a, b) {
        if (fs.sort === 'asset') return String(a.assetLabel).localeCompare(String(b.assetLabel));
        if (fs.sort === 'recent') return b.discoveredAt - a.discoveredAt;
        const d = CT.data.SEV_RANK[a.severity] - CT.data.SEV_RANK[b.severity];
        return d !== 0 ? d : String(a.assetLabel).localeCompare(String(b.assetLabel));
      }

      // Windowed rows are pinned to a uniform height, so this must clear a
      // two-line title plus the severity and meta rows.
      const vlist = new CT.dom.VirtualList({
        scrollEl: S.els.view, itemHeight: 108, threshold: 90,
        renderItem: (f) => S.findingRow(f)
      });

      function refresh() {
        const filtered = all.filter(matches).sort(sortFn);
        countLine.textContent = filtered.length + ' of ' + all.length;
        CT.dom.clear(listBox);
        if (!filtered.length) {
          listBox.appendChild(CT.dom.empty({
            icon: fs.status === 'open' && fs.severity === 'all' ? 'shieldCheck' : 'search',
            title: fs.status === 'open' && fs.severity === 'all' && !fs.query ? 'No open findings' : 'Nothing matches',
            body: fs.status === 'open' && fs.severity === 'all' && !fs.query
              ? 'Every finding in this assessment has been resolved or accepted.'
              : 'Adjust the filters or search term to see other findings.',
            secondary: { label: 'Reset filters', onClick: () => { fs = { severity: 'all', status: 'all', query: '', sort: 'severity' }; S.render(); } }
          }));
        } else {
          listBox.appendChild(vlist.root);
          vlist.setItems(filtered);
          vlist.attach();
        }
      }

      const sevChips = h('div.chips', { role: 'group', 'aria-label': 'Filter by severity' },
        [{ id: 'all', label: 'All' }].concat(CT.data.SEVERITIES.map((s) => ({ id: s, label: CT.data.SEV_LABEL[s] })))
          .map((opt) => {
            const n = all.filter((f) => {
              const st = f.status || 'open';
              const statusOk = fs.status === 'all' ? true
                : fs.status === 'open' ? (st !== 'resolved' && st !== 'accepted') : st === fs.status;
              return statusOk && (opt.id === 'all' || f.severity === opt.id);
            }).length;
            return h('button.chip', {
              type: 'button', 'aria-pressed': fs.severity === opt.id ? 'true' : 'false',
              onClick: () => { fs.severity = opt.id; S.render(); }
            }, [
              opt.id !== 'all' ? h('span.status-dot.' + (opt.id === 'informational' ? 'info' : opt.id), { 'aria-hidden': 'true' }) : null,
              h('span', opt.label), h('span.n', String(n))
            ]);
          }));

      container.appendChild(S.simulatedBanner(cur));
      container.appendChild(h('div.search-bar', [
        icon('search'),
        h('input', {
          type: 'search', value: fs.query, placeholder: 'Search title, asset, rule ID',
          'aria-label': 'Search findings',
          on: { input: CT.util.debounce(function () { fs.query = this.value; refresh(); }, 140) }
        })
      ]));
      container.appendChild(sevChips);
      container.appendChild(h('div.row.gap8', [
        h('div.segmented.grow', { role: 'group', 'aria-label': 'Filter by status' },
          [['open', 'Open'], ['resolved', 'Resolved'], ['accepted', 'Accepted'], ['all', 'All']].map(([id, label]) =>
            h('button', { type: 'button', 'aria-pressed': fs.status === id ? 'true' : 'false',
              onClick: () => { fs.status = id; S.render(); } }, label))),
        h('button.icon-btn', {
          type: 'button', 'aria-label': 'Sort findings',
          onClick: () => sortSheet()
        }, icon('sort'))
      ]));
      container.appendChild(CT.dom.sectionLabel('Findings', countLine));
      container.appendChild(listBox);
      refresh();
      return container;
    }
  };

  function sortSheet() {
    const opts = [['severity', 'Severity (highest first)'], ['asset', 'Asset name'], ['recent', 'Most recently detected']];
    const s = S.sheet({
      title: 'Sort findings',
      body: h('div.list', opts.map(([id, label]) => h('button.list-item', {
        type: 'button', onClick: () => { fs.sort = id; s.close(); S.render(); }
      }, [
        h('span.grow', label),
        fs.sort === id ? h('span', { style: { color: 'var(--accent)', display: 'flex' } }, icon('check')) : null
      ])))
    });
  }

  /* ==========================================================================
     DETAIL
     ======================================================================= */
  CT.ui.routes.finding = {
    parent: '#/findings', tab: 'findings',
    title: () => 'Finding',
    subtitle: (p) => {
      const f = CT.store.findingById(p[0]);
      return f ? f.ruleId : null;
    },
    render(params) {
      const f = CT.store.findingById(params[0]);
      if (!f) {
        return CT.dom.empty({
          icon: 'search', title: 'Finding not found',
          body: 'This finding is not part of the assessment currently loaded. It may belong to an earlier scan.',
          action: { label: 'Back to findings', onClick: () => S.navigate('#/findings') }
        });
      }
      const asset = f.assetId ? CT.store.assetById(f.assetId) : null;
      const status = f.status || 'open';
      const rt = CT.data.rule(f.ruleId);

      return h('div.stack.gap12', [
        f.simulated ? h('div.demo-banner', [icon('alert'), h('div.grow', [
          h('strong', 'SIMULATED'), ' — derived from demo environment data.'])]) : null,

        h('div.card', [
          h('div.row.gap8.wrap.mb8', [
            S.severityPill(f.severity),
            h('span.tag', f.ruleId),
            h('span.tag', f.category),
            status !== 'open' ? h('span.pill.' + (status === 'resolved' ? 'ok' : 'neutral'), STATUS_LABEL[status]) : null
          ]),
          h('h2', { style: { 'font-size': '1.12em', 'line-height': '1.3' } }, f.title),
          f.detail ? h('p.small.dim.mt8', { style: { margin: '8px 0 0' } }, f.detail) : null
        ]),

        h('div.card', [
          h('dl', [
            CT.dom.kv('Asset', asset
              ? h('button.btn.sm.quiet', { type: 'button', style: { padding: '2px 6px', 'min-height': '0' },
                  onClick: () => S.navigate('#/asset/' + asset.id) }, [f.assetLabel, icon('chevronRight')])
              : f.assetLabel),
            f.assetIp ? CT.dom.kv('Address', f.assetIp, { mono: true }) : null,
            f.service ? CT.dom.kv('Service', f.service, { mono: true }) : null,
            CT.dom.kv('Confidence', CT.util.titleCase(f.confidence)),
            CT.dom.kv('First detected', CT.util.fmtDateTime(f.discoveredAt)),
            CT.dom.kv('Status', STATUS_LABEL[status]),
            f.assignee ? CT.dom.kv('Assigned to', f.assignee) : null
          ])
        ]),

        section('Description', 'info', h('p.small', { style: { color: 'var(--text-2)', 'line-height': '1.55' } }, rt.description)),
        section('Risk', 'alert', h('p.small', { style: { color: 'var(--text-2)', 'line-height': '1.55' } }, rt.impact)),

        section('Evidence', 'terminal', h('div', [
          h('p.tiny.muted.mb8', { style: { margin: '0 0 8px' } },
            'Observed technical facts. No credential, key or session material is ever captured or stored.'),
          f.evidence && f.evidence.length
            ? h('div', f.evidence.map((e) => h('div.evidence', [
              h('div.e-label', e.label),
              h('div.e-value', e.value)
            ])))
            : h('p.small.muted', 'No structured evidence recorded for this finding.')
        ])),

        section('Recommended remediation', 'shieldCheck', h('div',
          (rt.remediation || []).length
            ? h('ol', { style: { margin: 0, 'padding-left': '20px', 'font-size': '0.86em', color: 'var(--text-2)', 'line-height': '1.65' } },
              rt.remediation.map((r) => h('li', r)))
            : h('p.small.muted', 'No remediation guidance recorded.'))),

        (rt.references || []).length ? section('References', 'book',
          h('div.row.wrap.gap6', rt.references.map((r) => h('span.tag', r)))) : null,

        (f.notes || []).length ? section('Notes', 'note', h('div.list',
          f.notes.map((n) => h('div.list-item.static', { style: { display: 'block', padding: '9px 0' } }, [
            h('div.tiny.muted', CT.util.fmtDateTime(n.ts) + ' · ' + n.author),
            h('div.small.mt4', n.text)
          ])))) : null,

        h('div', [
          CT.dom.sectionLabel('Actions'),
          h('div.btn-grid', [
            h('button.btn' + (status === 'resolved' ? '' : '.primary'), {
              type: 'button',
              onClick: () => {
                const next = status === 'resolved' ? 'open' : 'resolved';
                CT.store.setFindingStatus(f.id, next);
                S.toast(next === 'resolved' ? 'Marked as resolved — score updated' : 'Reopened', 'ok');
                S.render();
              }
            }, [icon('check'), status === 'resolved' ? 'Reopen' : 'Mark as resolved']),
            h('button.btn', {
              type: 'button',
              onClick: () => {
                if (status === 'accepted') { CT.store.setFindingStatus(f.id, 'open'); S.render(); return; }
                S.prompt({
                  title: 'Accept risk',
                  body: 'Accepting a risk removes it from the score. Record who accepted it and why.',
                  label: 'Justification', multiline: true,
                  placeholder: 'Compensating control, business justification, review date…'
                }).then((reason) => {
                  if (reason === null) return;
                  CT.store.setFindingStatus(f.id, 'accepted');
                  if (reason.trim()) CT.store.addFindingNote(f.id, 'Risk accepted: ' + reason.trim());
                  S.toast('Risk accepted', 'ok');
                  S.render();
                });
              }
            }, [icon('shield'), status === 'accepted' ? 'Un-accept' : 'Accept risk']),
            h('button.btn', {
              type: 'button',
              onClick: () => S.prompt({ title: 'Assign finding', label: 'Assignee', value: f.assignee || '', placeholder: 'Name or team' })
                .then((v) => { if (v !== null) { CT.store.assignFinding(f.id, v.trim() || null); S.toast(v.trim() ? 'Assigned to ' + v.trim() : 'Assignment cleared', 'ok'); S.render(); } })
            }, [icon('user'), 'Assign']),
            h('button.btn', {
              type: 'button',
              onClick: () => S.prompt({ title: 'Add note', label: 'Note', multiline: true, placeholder: 'Investigation detail, ticket reference…' })
                .then((v) => { if (v && v.trim()) { CT.store.addFindingNote(f.id, v.trim()); S.toast('Note added', 'ok'); S.render(); } })
            }, [icon('note'), 'Add note'])
          ]),
          h('button.btn.ghost.block.mt8', {
            type: 'button',
            onClick: () => { CT.ui.reportPreset = 'findings'; S.navigate('#/reports'); }
          }, [icon('report'), 'Create report'])
        ]),

        h('div.notice', [icon('shield'), h('div.grow', [
          h('strong', 'Verify before acting'),
          h('span', 'CheckerTracker reports observed configuration state. It does not confirm exploitability. Validate this finding manually inside the authorized environment before making changes.')
        ])])
      ]);
    }
  };

  function section(title, iconName, content) {
    return h('div.card', [
      h('div.card-head', [icon(iconName), h('h3', title)]),
      content
    ]);
  }
})();
