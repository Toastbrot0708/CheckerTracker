/* ============================================================================
   MODULE: CT.ui.shell — router, chrome, overlays, shared components
   ========================================================================= */
CT.ui = CT.ui || {};

CT.ui.shell = (function () {
  'use strict';
  const h = CT.dom.h, icon = CT.dom.icon;

  const els = {
    root: document.getElementById('ct-root'),
    appbar: document.getElementById('ct-appbar'),
    view: document.getElementById('ct-view'),
    tabbar: document.getElementById('ct-tabbar'),
    overlay: document.getElementById('ct-overlay-root'),
    sheetRoot: document.getElementById('ct-sheet-root'),
    toastRoot: document.getElementById('ct-toast-root')
  };

  const TABS = [
    { id: 'dashboard', label: 'Dashboard', icon: 'dashboard', route: '#/dashboard' },
    { id: 'discover', label: 'Discover', icon: 'radar', route: '#/discover' },
    { id: 'scan', label: 'Scan', icon: 'crosshair', route: '#/scan' },
    { id: 'findings', label: 'Findings', icon: 'alert', route: '#/findings' },
    { id: 'more', label: 'More', icon: 'more', route: '#/more' }
  ];

  let currentRoute = null;
  let scrollMemory = {};

  /* -- Routing ------------------------------------------------------------- */
  function parseHash() {
    const raw = (location.hash || '#/dashboard').replace(/^#\/?/, '');
    const parts = raw.split('/').filter(Boolean).map(decodeURIComponent);
    return { name: parts[0] || 'dashboard', params: parts.slice(1), raw: '#/' + parts.join('/') };
  }

  function navigate(route, replace) {
    if (replace) location.replace(route);
    else location.hash = route;
  }

  function back() {
    const r = parseHash();
    const def = CT.ui.routes[r.name];
    if (history.length > 1) history.back();
    else navigate((def && def.parent) || '#/dashboard', true);
  }

  function render() {
    const r = parseHash();
    const def = CT.ui.routes[r.name] || CT.ui.routes.dashboard;

    if (currentRoute && els.view) scrollMemory[currentRoute] = els.view.scrollTop;
    currentRoute = r.raw;

    CT.dom.destroyLists();
    renderAppbar(def, r);
    renderTabbar(def);

    CT.dom.clear(els.view);
    let content;
    try {
      content = def.render(r.params, r);
    } catch (err) {
      console.error('[ui] render failed for', r.raw, err);
      content = CT.dom.notice('err', 'This screen could not be rendered',
        (err && err.message) || 'An unexpected error occurred.',
        { label: 'Return to dashboard', onClick: () => navigate('#/dashboard') });
    }
    els.view.appendChild(content);

    const keep = def.keepScroll && scrollMemory[r.raw];
    els.view.scrollTop = keep || 0;
    if (def.focusOnEnter !== false) els.view.focus({ preventScroll: true });
    document.title = (def.title ? def.title(r.params) + ' · ' : '') + 'CheckerTracker';
  }

  function renderAppbar(def, r) {
    const cur = CT.store.currentAssessment();
    const showDemo = cur && cur.simulated && CT.store.state.settings.showDemoWatermark;
    const unread = CT.store.unreadCount();
    const title = def.title ? def.title(r.params) : 'CheckerTracker';
    const sub = def.subtitle ? def.subtitle(r.params) : null;

    CT.dom.mount(els.appbar, h('div.appbar-row', [
      def.parent
        ? h('button.icon-btn', { type: 'button', 'aria-label': 'Back', onClick: back }, icon('chevronLeft'))
        : h('span', { style: { width: '4px' } }),
      h('div.appbar-title', [
        h('h1', title),
        sub ? h('span.sub', sub) : null
      ]),
      h('div.appbar-actions', [
        showDemo ? h('span.demo-chip', { title: 'Results come from a simulated environment' }, 'Demo data') : null,
        def.actions ? def.actions(r.params) : null,
        h('button.icon-btn', {
          type: 'button',
          'aria-label': unread ? 'Notifications, ' + unread + ' unread' : 'Notifications',
          style: { position: 'relative' },
          onClick: () => navigate('#/notifications')
        }, [icon('bell'), unread ? h('span.badge-count', { 'aria-hidden': 'true' }, unread > 99 ? '99+' : String(unread)) : null])
      ])
    ]));
  }

  function renderTabbar(def) {
    const activeTab = def.tab || null;
    const crit = CT.store.activeFindings().filter((f) => f.severity === 'critical').length;
    CT.dom.mount(els.tabbar, TABS.map((t) => h('button.tab', {
      type: 'button',
      'aria-current': activeTab === t.id ? 'page' : null,
      'aria-label': t.label + (t.id === 'findings' && crit ? ', ' + crit + ' critical' : ''),
      onClick: () => navigate(t.route)
    }, [
      icon(t.icon),
      h('span', t.label),
      t.id === 'findings' && crit ? h('span.dot', { 'aria-hidden': 'true' }) : null
    ])));
  }

  /** Refresh only the app bar and tab bar (badges, counters) — never the view,
      so focus and in-progress input in the current screen are preserved. */
  function renderChrome() {
    const r = parseHash();
    const def = CT.ui.routes[r.name] || CT.ui.routes.dashboard;
    renderAppbar(def, r);
    renderTabbar(def);
  }

  /* -- Overlays ------------------------------------------------------------ */
  let sheetStack = [];

  function sheet(opts) {
    const scrim = h('div.scrim', { onClick: () => close() });
    const panel = h('div.sheet', { role: 'dialog', 'aria-modal': 'true', 'aria-label': opts.title || 'Dialog' }, [
      h('div.sheet-grip', { 'aria-hidden': 'true' }),
      h('div.sheet-head', [
        h('h2', opts.title || ''),
        h('button.icon-btn', { type: 'button', 'aria-label': 'Close', onClick: () => close() }, icon('close'))
      ]),
      h('div.sheet-body', opts.body),
      opts.footer ? h('div.sheet-foot', opts.footer) : null
    ]);
    els.sheetRoot.appendChild(scrim);
    els.sheetRoot.appendChild(panel);
    const entry = { scrim, panel, onClose: opts.onClose };
    sheetStack.push(entry);
    document.addEventListener('keydown', escHandler);
    const focusable = panel.querySelector('button, input, textarea, select, a[href]');
    if (focusable) setTimeout(() => focusable.focus(), 30);

    function close(result) {
      const i = sheetStack.indexOf(entry);
      if (i === -1) return;
      sheetStack.splice(i, 1);
      scrim.remove(); panel.remove();
      if (!sheetStack.length) document.removeEventListener('keydown', escHandler);
      if (entry.onClose) entry.onClose(result);
    }
    entry.close = close;
    return { close, panel };
  }

  function escHandler(e) {
    if (e.key === 'Escape' && sheetStack.length) {
      e.preventDefault();
      sheetStack[sheetStack.length - 1].close();
    }
  }

  function confirm(opts) {
    return new Promise((resolve) => {
      let settled = false;
      const s = sheet({
        title: opts.title,
        body: h('div', [
          h('p.dim', { style: { 'font-size': '0.9em' } }, opts.body),
          opts.detail ? h('div.notice.mt12', [icon('info'), h('div.grow', opts.detail)]) : null
        ]),
        footer: h('div.btn-row', [
          h('button.btn.ghost', { type: 'button', onClick: () => { settled = true; s.close(); resolve(false); } }, opts.cancelLabel || 'Cancel'),
          h('button.btn' + (opts.danger ? '.danger' : '.primary'), {
            type: 'button', onClick: () => { settled = true; s.close(); resolve(true); }
          }, opts.confirmLabel || 'Confirm')
        ]),
        onClose: () => { if (!settled) resolve(false); }
      });
    });
  }

  function prompt(opts) {
    return new Promise((resolve) => {
      let settled = false;
      let input;
      const field = opts.multiline
        ? h('textarea', { placeholder: opts.placeholder || '', ref: (e) => { input = e; } }, opts.value || '')
        : h('input', { type: opts.type || 'text', value: opts.value || '', placeholder: opts.placeholder || '', ref: (e) => { input = e; } });
      const s = sheet({
        title: opts.title,
        body: h('div', [
          opts.body ? h('p.dim.small.mb12', opts.body) : null,
          h('label.field', [opts.label ? h('span.lbl', opts.label) : null, field])
        ]),
        footer: h('div.btn-row', [
          h('button.btn.ghost', { type: 'button', onClick: () => { settled = true; s.close(); resolve(null); } }, 'Cancel'),
          h('button.btn.primary', {
            type: 'button',
            onClick: () => { settled = true; const v = input.value; s.close(); resolve(v); }
          }, opts.confirmLabel || 'Save')
        ]),
        onClose: () => { if (!settled) resolve(null); }
      });
    });
  }

  function toast(message, kind, ms) {
    const t = h('div.toast' + (kind ? '.' + kind : ''), [
      icon(kind === 'err' ? 'alertCircle' : kind === 'warn' ? 'alert' : kind === 'ok' ? 'check' : 'info'),
      h('div.grow', message)
    ]);
    els.toastRoot.appendChild(t);
    setTimeout(() => {
      t.style.transition = 'opacity 200ms, transform 200ms';
      t.style.opacity = '0';
      t.style.transform = 'translateY(6px)';
      setTimeout(() => t.remove(), 220);
    }, ms || 2800);
  }

  /* -- Export ---------------------------------------------------------------
     Sandboxed viewers block page-initiated downloads, so every export also
     offers copy-to-clipboard and an inspectable payload. Nothing is uploaded. */
  function exportData(opts) {
    const { filename, mime, content, title } = opts;
    const canDownload = CT.engines.capabilities.downloadSupported();
    const sizeLabel = CT.util.fmtBytes(new Blob([content]).size);

    const body = h('div', [
      h('div.notice.accent.mb12', [
        icon('shield'),
        h('div.grow', [
          h('strong', 'Local export'),
          h('span', 'This payload is generated on the device. It is not uploaded anywhere. Review it before sharing — it contains your asset inventory.')
        ])
      ]),
      h('dl.mb12', [
        CT.dom.kv('File', filename, { mono: true }),
        CT.dom.kv('Type', mime),
        CT.dom.kv('Size', sizeLabel)
      ]),
      h('div.section-label', [h('span', 'Payload preview'), h('span.line')]),
      h('pre.code', { style: { 'max-height': '240px', 'overflow-y': 'auto' } },
        content.length > 20000 ? content.slice(0, 20000) + '\n\n… truncated in preview (' + sizeLabel + ' total, full content is copied)' : content)
    ]);

    const s = sheet({
      title: title || 'Export',
      body,
      footer: h('div.stack.gap8', [
        h('div.btn-row', [
          h('button.btn.ghost', {
            type: 'button',
            onClick: () => CT.util.copyText(content).then((ok) => toast(ok ? 'Copied to clipboard' : 'Clipboard unavailable in this context', ok ? 'ok' : 'warn'))
          }, [icon('copy'), 'Copy']),
          h('button.btn.primary', {
            type: 'button',
            onClick: () => {
              if (!canDownload) { toast('Downloads are blocked in this viewer — use Copy instead', 'warn', 4000); return; }
              try {
                const blob = new Blob([content], { type: mime });
                const url = URL.createObjectURL(blob);
                const a = h('a', { href: url, download: filename, style: { display: 'none' } });
                document.body.appendChild(a);
                a.click();
                setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1500);
                CT.store.audit('export', 'Exported ' + filename + ' (' + sizeLabel + ')');
                CT.store.commit();
                toast('Export started', 'ok');
              } catch (e) { toast('Download blocked by the browser — use Copy instead', 'warn', 4000); }
            }
          }, [icon('download'), 'Download'])
        ]),
        !canDownload ? h('p.tiny.muted.center', { style: { margin: 0 } },
          'File downloads are unavailable in this runtime. Copy the payload instead.') : null
      ])
    });
    return s;
  }

  /** Route an export through the confirmation gate when export control is on. */
  function guardedExport(opts) {
    if (!CT.store.state.settings.exportRequiresConfirm) { exportData(opts); return; }
    confirm({
      title: 'Confirm export',
      body: 'Privacy Mode keeps scan results on this device. Exporting creates a copy you are responsible for handling.',
      detail: opts.filename + ' — ' + (opts.summary || 'assessment data'),
      confirmLabel: 'Continue'
    }).then((ok) => { if (ok) exportData(opts); });
  }

  /* -- Shared components ---------------------------------------------------- */
  function severityPill(sev, opts) {
    const o = opts || {};
    return h('span.pill.' + (sev === 'informational' ? 'info' : sev), [
      h('span.glyph', { 'aria-hidden': 'true' }, CT.data.SEV_GLYPH[sev]),
      h('span', o.short ? CT.data.SEV_LABEL[sev].slice(0, 4) : CT.data.SEV_LABEL[sev])
    ]);
  }

  function confidencePill(c) {
    const kind = c === 'high' ? 'neutral' : c === 'medium' ? 'neutral' : 'neutral';
    return h('span.tag', { title: 'Confidence: ' + c }, [CT.util.titleCase(c) + ' confidence']);
  }

  function riskDot(level, label) {
    return h('span.row.gap6', [
      h('span.status-dot.' + (level === 'ok' ? 'ok' : level === 'informational' ? 'info' : level), { 'aria-hidden': 'true' }),
      h('span.tiny.dim', label)
    ]);
  }

  function deviceIcon(type) { return icon(CT.icons.DEVICE_ICON[type] || 'unknown'); }

  function demoBadge() { return h('span.demo-chip', 'Demo data'); }

  function simulatedBanner(assessment) {
    if (!assessment) return null;
    if (assessment.imported) {
      return h('div.demo-banner', [
        icon('info'),
        h('div.grow', [h('strong', 'IMPORTED DATASET'), ' — findings were recomputed locally from the imported inventory.'])
      ]);
    }
    if (!assessment.simulated) return null;
    return h('div.demo-banner', [
      icon('alert'),
      h('div.grow', [
        h('strong', 'SIMULATED ASSESSMENT'),
        ' — no real system was contacted. Hosts, services and banners come from the "' +
        assessment.environmentName + '" demo environment; every finding below was computed from that data by the analysis engines.'
      ])
    ]);
  }

  function assetRow(asset, risk, onClick) {
    const svcCount = (asset.services || []).length;
    return h('button.list-item', {
      type: 'button',
      onClick: onClick || (() => navigate('#/asset/' + asset.id)),
      'aria-label': (asset.hostname || asset.ip) + ', ' + asset.deviceType + ', ' + risk.label
    }, [
      h('span.status-dot.' + (risk.level === 'ok' ? 'ok' : risk.level), { 'aria-hidden': 'true' }),
      h('span.grow.stack', { style: { 'min-width': '0' } }, [
        h('span.row.gap6', [
          h('span.trunc', { style: { 'font-size': '0.9em', 'font-weight': '600' } }, asset.hostname || asset.ip),
          asset.inInventory === false ? h('span.tag', { style: { 'flex': '0 0 auto' } }, 'unknown') : null
        ]),
        h('span.tiny.muted.trunc', [
          h('span.mono', asset.ip), ' · ', asset.deviceType,
          asset.vendor ? ' · ' + asset.vendor : '',
          svcCount ? ' · ' + CT.util.plural(svcCount, 'service') : ' · no services'
        ])
      ]),
      h('span.stack', { style: { 'align-items': 'flex-end', 'flex': '0 0 auto' } }, [
        risk.level === 'ok'
          ? h('span.tiny.muted', 'clear')
          : h('span.tiny', { style: { color: 'var(--sev-' + risk.level + ')', 'font-weight': '650' } }, risk.score),
        h('span.tiny.muted', CT.util.fmtRelative(asset.lastSeen))
      ]),
      icon('chevronRight', { cls: 'chev' })
    ]);
  }

  function findingRow(f, onClick) {
    return h('button.list-item', {
      type: 'button',
      onClick: onClick || (() => navigate('#/finding/' + encodeURIComponent(f.id))),
      'aria-label': CT.data.SEV_LABEL[f.severity] + ': ' + f.title + ' on ' + f.assetLabel
    }, [
      h('span.grow.stack', { style: { 'min-width': '0' } }, [
        h('span.row.gap6.wrap', [
          severityPill(f.severity, { short: false }),
          f.status && f.status !== 'open' ? h('span.tag', f.status.replace('_', ' ')) : null
        ]),
        h('span.mt4', { style: { 'font-size': '0.89em', 'font-weight': '600', 'line-height': '1.35' } }, f.title),
        h('span.tiny.muted.trunc.mt4', [
          f.assetLabel, f.service ? ' · ' + f.service : '', ' · ', f.ruleId
        ])
      ]),
      icon('chevronRight', { cls: 'chev' })
    ]);
  }

  function metric(value, label, kind, onClick) {
    const props = { class: 'metric' + (kind ? ' ' + kind : '') };
    const inner = [h('div.v', String(value)), h('div.l', label)];
    if (onClick) return h('button.metric' + (kind ? '.' + kind : ''), { type: 'button', onClick, 'aria-label': label + ': ' + value }, inner);
    return h('div', props, inner);
  }

  function severityBar(counts, total) {
    const t = total || CT.data.SEVERITIES.reduce((a, s) => a + (counts[s] || 0), 0);
    if (!t) return null;
    return h('div', [
      h('div.sev-bar', { role: 'img', 'aria-label': CT.data.SEVERITIES.map((s) => (counts[s] || 0) + ' ' + s).join(', ') },
        CT.data.SEVERITIES.map((s) => counts[s]
          ? h('i', { style: { width: (counts[s] / t * 100) + '%', background: s === 'informational' ? 'var(--sev-info)' : 'var(--sev-' + s + ')' } })
          : null)),
      h('div.sev-legend', CT.data.SEVERITIES.filter((s) => counts[s]).map((s) =>
        h('span', [
          h('span.status-dot.' + (s === 'informational' ? 'info' : s), { 'aria-hidden': 'true' }),
          h('span', counts[s] + ' ' + CT.data.SEV_LABEL[s])
        ])))
    ]);
  }

  function capabilityNote(capId) {
    const c = CT.engines.capabilities.get(capId);
    const kind = c.mode === 'real' ? 'ok' : c.mode === 'simulated' ? 'warn' : 'warn';
    return h('div.notice.' + kind, [
      icon(c.mode === 'real' ? 'shieldCheck' : 'info'),
      h('div.grow', [
        h('strong', c.mode === 'real' ? 'Real analysis' : c.mode === 'simulated' ? 'Simulated' : 'Not available in this runtime'),
        h('span', c.reason),
        c.fallback ? h('span.tiny.muted', { style: { display: 'block', 'margin-top': '4px' } }, c.fallback) : null
      ])
    ]);
  }

  function emptyNoAssessment(what) {
    return CT.dom.empty({
      icon: 'inbox',
      title: 'No assessment yet',
      body: 'Run an authorized assessment to populate ' + what + '.',
      action: { label: 'Open Scan Center', icon: 'crosshair', onClick: () => navigate('#/scan') },
      secondary: { label: 'Load the demo environment', onClick: () => { CT.store.seedDemo(CT.store.state.environmentId); toast('Demo environment loaded', 'ok'); render(); } }
    });
  }

  return {
    els, TABS, parseHash, navigate, back, render, renderChrome,
    sheet, confirm, prompt, toast, exportData, guardedExport,
    severityPill, confidencePill, riskDot, deviceIcon, demoBadge, simulatedBanner,
    assetRow, findingRow, metric, severityBar, capabilityNote, emptyNoAssessment
  };
})();
