/* ============================================================================
   MODULE: CT.ui.routes.scan — Scan Center (wizard, authorization, progress)
   ========================================================================= */
(function () {
  'use strict';
  const h = CT.dom.h, icon = CT.dom.icon, S = CT.ui.shell;

  const SCOPE_MODES = [
    { id: 'current', label: 'Current network' },
    { id: 'cidr', label: 'Custom CIDR' },
    { id: 'host', label: 'Single host' },
    { id: 'group', label: 'Asset group' },
    { id: 'saved', label: 'Saved scope' }
  ];

  let wiz = null;
  let lastError = null;
  let lastResult = null;

  function defaultScope() {
    const cur = CT.store.currentAssessment();
    if (cur && cur.network) return cur.network.subnet;
    const env = CT.demo.build(CT.store.state.environmentId || 'corp-lab');
    return env.network.subnet;
  }

  function resetWizard() {
    wiz = {
      step: 0,
      mode: 'current',
      scopeText: defaultScope(),
      groupId: 'servers',
      savedId: null,
      profileId: 'full',
      environmentId: CT.store.state.environmentId || 'corp-lab',
      authorized: false,
      windowHours: 24
    };
  }

  function scopeFromMode() {
    if (!wiz) resetWizard();
    if (wiz.mode === 'group') {
      const assets = CT.store.assets().filter((a) => CT.data.DEVICE_GROUP[a.deviceType] === wiz.groupId);
      return assets.map((a) => a.ip).join(', ');
    }
    return wiz.scopeText;
  }

  function validateScope() {
    const text = scopeFromMode();
    if (!text || !text.trim()) return { ok: false, error: 'No scope defined.' };
    try { return { ok: true, scope: CT.net.parseScope(text) }; }
    catch (e) { return { ok: false, error: e.message }; }
  }

  /* ==========================================================================
     ROUTE
     ======================================================================= */
  CT.ui.routes.scan = {
    tab: 'scan',
    title: () => 'Scan Center',
    subtitle: () => {
      const r = CT.engines.scanner.currentRun();
      return r ? 'Assessment running · ' + r.progress + '%' : 'Authorized assessment workflow';
    },
    render() {
      const run = CT.engines.scanner.currentRun();
      if (run) return progressView(run);
      if (lastResult) return resultView(lastResult);
      if (!wiz) resetWizard();
      return wizardView();
    }
  };

  /* ==========================================================================
     WIZARD
     ======================================================================= */
  function wizardView() {
    const steps = ['Scope', 'Scan type', 'Authorize'];
    return h('div.stack.gap12', [
      h('div.steps', { role: 'progressbar', 'aria-valuemin': '1', 'aria-valuemax': '3',
                       'aria-valuenow': String(wiz.step + 1), 'aria-label': 'Step ' + (wiz.step + 1) + ' of 3: ' + steps[wiz.step] },
        steps.map((s, i) => h('span.step-dot', { dataset: { state: i < wiz.step ? 'done' : i === wiz.step ? 'active' : 'pending' } }))),
      h('div.row.gap8', [
        h('span.tiny.muted', 'Step ' + (wiz.step + 1) + ' of 3'),
        h('span.grow'),
        h('span.tiny', { style: { 'font-weight': '650' } }, steps[wiz.step])
      ]),
      lastError ? errorNotice(lastError) : null,
      wiz.step === 0 ? stepScope() : wiz.step === 1 ? stepProfile() : stepAuthorize(),
      wizardFooter()
    ]);
  }

  function wizardFooter() {
    const v = validateScope();
    const canNext = wiz.step === 0 ? v.ok : true;
    return h('div.wizard-foot', h('div.btn-row', [
      wiz.step > 0 ? h('button.btn.ghost', { type: 'button', onClick: () => { wiz.step--; S.render(); } }, [icon('chevronLeft'), 'Back']) : null,
      wiz.step < 2
        ? h('button.btn.primary', {
          type: 'button', disabled: !canNext,
          onClick: () => { if (canNext) { wiz.step++; lastError = null; S.render(); } }
        }, ['Continue', icon('chevronRight')])
        : h('button.btn.primary', {
          type: 'button', disabled: !wiz.authorized,
          'aria-disabled': wiz.authorized ? null : 'true',
          onClick: startScan
        }, [icon('play'), 'Start assessment'])
    ]));
  }

  /* -- Step 1: scope -------------------------------------------------------- */
  function stepScope() {
    const v = validateScope();
    const box = h('div.stack.gap12');

    box.appendChild(h('div.card', [
      h('div.card-head', [icon('scope'), h('h3', 'Define the authorized scope')]),
      h('p.small.dim.mb12', 'Active checks are constrained to exactly these addresses. Nothing outside the scope is contacted.'),
      h('div.segmented.mb12', { role: 'group', 'aria-label': 'Scope type' }, SCOPE_MODES.map((m) =>
        h('button', {
          type: 'button', 'aria-pressed': wiz.mode === m.id ? 'true' : 'false',
          onClick: () => {
            wiz.mode = m.id;
            if (m.id === 'current') wiz.scopeText = defaultScope();
            if (m.id === 'cidr') wiz.scopeText = '192.168.1.0/24';
            if (m.id === 'host') wiz.scopeText = '192.168.1.20';
            if (m.id === 'saved' && CT.store.state.savedScopes.length) {
              wiz.savedId = CT.store.state.savedScopes[0].id;
              wiz.scopeText = CT.store.state.savedScopes[0].value;
            }
            S.render();
          }
        }, m.label))),
      scopeInput()
    ]));

    if (v.ok) {
      const scope = v.scope;
      const first = scope.entries[0];
      box.appendChild(h('div.card', { style: { 'border-color': 'var(--accent-line)', background: 'var(--accent-dim)' } }, [
        h('div.section-label', { style: { color: 'var(--accent-2)' } }, 'Authorized scope'),
        h('div.mono', { style: { 'font-size': '1.05em', 'font-weight': '650', 'word-break': 'break-word' } },
          scope.label.length > 90 ? scope.label.slice(0, 90) + ' …' : scope.label),
        h('div.tiny.muted.mt6', CT.util.plural(scope.entries.length, 'entry', 'entries') + ' · ' +
          CT.util.fmtNum(scope.totalHosts) + ' addresses in scope'),
        first && first.info ? h('dl.mt12', [
          CT.dom.kv('Network', first.info.network, { mono: true }),
          CT.dom.kv('Netmask', first.info.netmask, { mono: true }),
          CT.dom.kv('Host range', first.info.rangeLabel, { mono: true }),
          CT.dom.kv('Usable hosts', CT.util.fmtNum(first.info.usableHosts), { mono: true }),
          CT.dom.kv('Address space', first.info.isPrivate ? 'RFC 1918 private' : 'Public / other')
        ]) : null,
        h('div.notice.accent.mt12', [icon('clock'), h('div.grow', [
          h('strong', wiz.windowHours + '-hour authorization window'),
          h('span', 'Confirmation applies to this scope only and lapses automatically after ' + wiz.windowHours + ' hours.')
        ])]),
        h('button.btn.sm.ghost.mt12', {
          type: 'button',
          onClick: () => S.prompt({ title: 'Save scope', label: 'Name', placeholder: 'e.g. Office segment' })
            .then((name) => { if (name) { CT.store.saveScope(name, scope.label); S.toast('Scope saved', 'ok'); } })
        }, [icon('plus'), 'Save this scope'])
      ]));
    } else {
      box.appendChild(CT.dom.notice('err', 'Scope invalid', v.error));
    }

    return box;
  }

  function scopeInput() {
    if (wiz.mode === 'group') {
      const groups = ['servers', 'workstations', 'mobile', 'iot', 'network', 'unknown'];
      const assets = CT.store.assets();
      if (!assets.length) return CT.dom.notice('warn', 'No inventory available', 'Asset groups require a completed assessment. Choose another scope type or load a demo environment.');
      return h('label.field', [
        h('span.lbl', 'Asset group'),
        h('select', {
          'aria-label': 'Asset group',
          on: { change: function () { wiz.groupId = this.value; S.render(); } }
        }, groups.map((g) => {
          const n = assets.filter((a) => CT.data.DEVICE_GROUP[a.deviceType] === g).length;
          return h('option', { value: g, selected: wiz.groupId === g ? true : null },
            CT.util.titleCase(g) + ' (' + n + ')');
        })),
        h('span.hint', 'Resolves to the current addresses of every asset in the group.')
      ]);
    }
    if (wiz.mode === 'saved') {
      const saved = CT.store.state.savedScopes;
      if (!saved.length) return CT.dom.notice('warn', 'No saved scopes', 'Define a CIDR scope and save it for reuse.');
      return h('label.field', [
        h('span.lbl', 'Saved scope'),
        h('select', {
          'aria-label': 'Saved scope',
          on: { change: function () { wiz.savedId = this.value; const s = saved.find((x) => x.id === this.value); if (s) wiz.scopeText = s.value; S.render(); } }
        }, saved.map((s) => h('option', { value: s.id, selected: wiz.savedId === s.id ? true : null }, s.name + ' — ' + s.value)))
      ]);
    }
    return h('label.field', [
      h('span.lbl', wiz.mode === 'host' ? 'Host address' : wiz.mode === 'cidr' ? 'CIDR block' : 'Detected network'),
      h('input', {
        type: 'text', value: wiz.scopeText, spellcheck: 'false', autocapitalize: 'off', autocorrect: 'off',
        readonly: wiz.mode === 'current' ? true : null,
        'aria-label': 'Scope',
        placeholder: wiz.mode === 'host' ? '192.168.1.20' : '192.168.1.0/24',
        on: { input: CT.util.debounce(function () { wiz.scopeText = this.value; S.render(); }, 350) }
      }),
      h('span.hint', wiz.mode === 'current'
        ? 'Taken from the loaded environment. Interface details cannot be read by a web runtime.'
        : 'IPv4 addresses, CIDR blocks (/16 or narrower) or hostnames. Separate multiple entries with commas.')
    ]);
  }

  /* -- Step 2: profile ------------------------------------------------------ */
  function stepProfile() {
    return h('div.stack.gap12', [
      h('div', [
        CT.dom.sectionLabel('Scan profile'),
        h('div', CT.engines.scanner.PROFILES.map((p) => h('button.profile-card', {
          type: 'button', 'aria-pressed': wiz.profileId === p.id ? 'true' : 'false',
          onClick: () => { wiz.profileId = p.id; S.render(); }
        }, [
          h('span.pico', icon(p.icon)),
          h('span.grow', [
            h('span.row.gap6', [h('span.ptitle', p.name), h('span.tag', p.intensity)]),
            h('span.pdesc', p.description),
            h('span.pmeta', p.stages.map((s) => CT.engines.scanner.STAGE_LABEL[s]).join(' → '))
          ])
        ])))
      ]),
      h('div.notice', [icon('shield'), h('div.grow', [
        h('strong', 'What no profile does'),
        h('span', 'None of these profiles attempt authentication, submit credentials, exercise a vulnerability, or change anything on a target. Where a check could only be completed by exploiting something, CheckerTracker reports the observation and asks you to verify it manually instead.')
      ])])
    ]);
  }

  /* -- Step 3: authorization ------------------------------------------------ */
  function stepAuthorize() {
    const v = validateScope();
    const profile = CT.engines.scanner.profileById(wiz.profileId);
    const canLive = CT.engines.capabilities.canRunLiveScan();
    const env = CT.demo.build(wiz.environmentId);
    const inScope = v.ok ? env.assets.filter((a) => v.scope.contains(a.ip)).length : 0;

    return h('div.stack.gap12', [
      h('div.card', [
        h('div.card-head', [icon('shieldCheck'), h('h3', 'Assessment summary')]),
        h('dl', [
          CT.dom.kv('Scope', v.ok ? (v.scope.label.length > 60 ? v.scope.label.slice(0, 60) + ' …' : v.scope.label) : '—', { mono: true }),
          CT.dom.kv('Addresses', v.ok ? CT.util.fmtNum(v.scope.totalHosts) : '—'),
          CT.dom.kv('Profile', profile.name),
          CT.dom.kv('Intensity', profile.intensity),
          CT.dom.kv('Stages', String(profile.stages.length)),
          CT.dom.kv('Authorization window', wiz.windowHours + ' hours')
        ])
      ]),

      h('div.card', [
        h('div.card-head', [icon('info'), h('h3', 'Execution mode')]),
        !canLive ? h('div.stack.gap10', [
          CT.dom.notice('warn', 'Active probing is not available in this runtime',
            'Host discovery and service enumeration need raw network access, which a web runtime does not provide. The assessment will therefore run against a declared demo environment and every result will be permanently marked as simulated.'),
          h('label.field', { style: { margin: 0 } }, [
            h('span.lbl', 'Demo environment to assess'),
            h('select', {
              'aria-label': 'Demo environment',
              on: { change: function () { wiz.environmentId = this.value; S.render(); } }
            }, CT.demo.ENVIRONMENTS.map((e) => h('option', { value: e.id, selected: wiz.environmentId === e.id ? true : null }, e.name + ' — ' + e.desc)))
          ]),
          h('div.row.gap8', [
            h('span.status-dot.' + (inScope ? 'ok' : 'medium'), { 'aria-hidden': 'true' }),
            h('span.tiny.dim', inScope
              ? CT.util.plural(inScope, 'simulated asset') + ' fall inside the declared scope'
              : 'No simulated asset falls inside this scope — the assessment will return no hosts')
          ])
        ]) : CT.dom.notice('ok', 'Active probing available', 'This runtime can perform real discovery within the authorized scope.')
      ]),

      h('div.card', [
        h('div.card-head', [icon('lock'), h('h3', 'Authorization')]),
        h('p.small.dim.mb12', 'Active security testing without the system owner\'s permission is unlawful in most jurisdictions. CheckerTracker records this confirmation in the audit log together with the scope and timestamp.'),
        h('label.check', [
          h('input', {
            type: 'checkbox', checked: wiz.authorized ? true : null,
            on: { change: function () { wiz.authorized = this.checked; S.render(); } }
          }),
          h('span.box', icon('check', { weight: '3' })),
          h('span.txt', 'I confirm that I am authorized to test these systems.')
        ]),
        !wiz.authorized ? h('p.tiny.muted.mt8', { style: { margin: '8px 0 0' } },
          'Active scans cannot start until this is confirmed.') : null
      ]),

      h('div.notice', [icon('list'), h('div.grow', [
        h('strong', 'Recorded with this run'),
        h('span', 'Scope, profile, confirmation timestamp, execution mode and the operator identity used by this device.')
      ])])
    ]);
  }

  /* -- Start ---------------------------------------------------------------- */
  function startScan() {
    lastError = null;
    const v = validateScope();
    if (!v.ok) { lastError = { code: 'scope', title: 'Scope invalid', body: v.error }; S.render(); return; }

    CT.store.grantAuthorization(v.scope.label, wiz.windowHours);
    const prev = CT.store.currentAssessment();

    let run;
    try {
      run = CT.engines.scanner.start({
        scopeText: scopeFromMode(),
        profileId: wiz.profileId,
        environmentId: wiz.environmentId,
        authorized: wiz.authorized,
        authorization: CT.store.state.authorization,
        baseline: prev ? prev.assets : null,
        baselineAt: prev ? prev.endedAt : null
      });
    } catch (e) {
      const def = CT.engines.scanner.ERRORS[e.code] || { title: 'Scan could not start' };
      lastError = { code: e.code || 'error', title: def.title, body: e.message };
      S.render();
      return;
    }

    run.on('done', (result) => {
      if (!result.assets.length) {
        lastError = { code: 'empty', title: CT.engines.scanner.ERRORS.empty.title, body: CT.engines.scanner.ERRORS.empty.body };
        lastResult = null;
        S.render();
        return;
      }
      const saved = CT.store.saveAssessment(result);
      lastResult = saved;
      S.render();
    });
    run.on('error', (err) => {
      if (err.code === 'cancelled') { lastError = err; lastResult = null; S.render(); }
    });

    S.render();
  }

  /* ==========================================================================
     PROGRESS VIEW — updates in place, no full re-render
     ======================================================================= */
  function progressView(run) {
    // This screen can be rebuilt while the run continues (navigate away and
    // back). Drop the previous rendering's listeners; the ones that persist
    // the result were registered on the durable channel when the run started.
    run.clearViewListeners();

    const pctEl = h('b', run.progress + '%');
    const barEl = CT.dom.bar(run.progress);
    const elapsedEl = h('div.v', CT.util.fmtClock(run.elapsedMs));
    const hostsEl = h('div.v', String(run.counters.hosts));
    const svcEl = h('div.v', String(run.counters.services));
    const findEl = h('div.v', String(run.counters.findings));
    const stagesBox = h('div');
    const logBox = h('div.scan-log', { role: 'log', 'aria-label': 'Assessment log' });
    const controls = h('div.btn-row');
    const liveRegion = h('div.sr-only', { role: 'status', 'aria-live': 'polite' });

    function paintStages() {
      CT.dom.mount(stagesBox, run.stages.map((s) => h('div.stage-row', { dataset: { state: s.state } }, [
        h('span.stage-ico', s.state === 'done' ? icon('check', { weight: '3' }) : null),
        h('span.stage-name', s.label),
        s.state === 'skipped' ? h('span.stage-meta', 'not in profile') : s.meta ? h('span.stage-meta', s.meta) : null
      ])));
    }

    function paintControls() {
      CT.dom.clear(controls);
      if (run.state === 'running') {
        controls.appendChild(h('button.btn.ghost', { type: 'button', onClick: () => { run.pause(); } }, [icon('pause'), 'Pause']));
      } else if (run.state === 'paused') {
        controls.appendChild(h('button.btn.primary', { type: 'button', onClick: () => { run.resume(); } }, [icon('play'), 'Resume']));
      }
      controls.appendChild(h('button.btn.danger', {
        type: 'button',
        onClick: () => S.confirm({
          title: 'Cancel assessment?', danger: true, confirmLabel: 'Cancel scan',
          body: 'The run stops immediately and no partial results are saved.'
        }).then((ok) => { if (ok) { run.cancel(); S.render(); } })
      }, [icon('stop'), 'Cancel']));
    }

    function appendLog(entry) {
      const line = h('div', [
        h('span.ts', CT.util.fmtTime(entry.ts) + '  '),
        h('span' + (entry.kind === 'hit' ? '.hit' : entry.kind === 'fnd' ? '.fnd' : ''), entry.text)
      ]);
      logBox.appendChild(line);
      logBox.scrollTop = logBox.scrollHeight;
    }

    run.log.forEach(appendLog);
    paintStages();
    paintControls();

    run.onView('progress', () => {
      pctEl.textContent = run.progress + '%';
      const fill = barEl.firstChild;
      if (fill) fill.style.width = run.progress + '%';
      elapsedEl.textContent = CT.util.fmtClock(run.elapsedMs);
      hostsEl.textContent = String(run.counters.hosts);
      svcEl.textContent = String(run.counters.services);
      findEl.textContent = String(run.counters.findings);
    });
    run.onView('stage', paintStages);
    run.onView('state', () => { paintControls(); liveRegion.textContent = 'Assessment ' + run.state; });
    run.onView('log', appendLog);
    run.onView('done', () => setTimeout(() => S.render(), 400));

    return h('div.stack.gap12', [
      liveRegion,
      h('div.demo-banner', [icon('alert'), h('div.grow', [
        h('strong', 'SIMULATED ASSESSMENT'),
        ' — running against the "' + run.environmentName + '" demo environment. No packet is sent to any network.'
      ])]),

      h('div.card', [
        h('div.row.gap8.mb8', [
          h('span.grow', [
            h('div', { style: { 'font-size': '0.95em', 'font-weight': '650' } },
              run.state === 'paused' ? 'Assessment paused' : 'Assessment running'),
            h('div.mono.tiny.muted', run.scopeLabel.length > 44 ? run.scopeLabel.slice(0, 44) + ' …' : run.scopeLabel)
          ]),
          h('div.progress-big', [pctEl])
        ]),
        barEl,
        h('div.row.gap8.mt8', [
          h('span.tag', run.profile.name),
          h('span.tag', run.profile.intensity),
          h('span.grow'),
          h('span.tiny.muted', CT.util.plural(run.counters.hostsTotal, 'target'))
        ])
      ]),

      h('div.metric-grid.c2', [
        h('div.metric', [elapsedEl, h('div.l', 'Elapsed')]),
        h('div.metric', [hostsEl, h('div.l', 'Hosts processed')])
      ]),
      h('div.metric-grid.c2', [
        h('div.metric', [svcEl, h('div.l', 'Services identified')]),
        h('div.metric', [findEl, h('div.l', 'Findings detected')])
      ]),

      h('div.card', [
        h('div.card-head', [icon('list'), h('h3', 'Stages')]),
        stagesBox
      ]),

      h('div.card', [
        h('div.card-head', [icon('terminal'), h('h3', 'Live log')]),
        logBox
      ]),

      controls
    ]);
  }

  /* ==========================================================================
     RESULT
     ======================================================================= */
  function resultView(result) {
    const prev = CT.store.state.assessments[CT.store.state.assessments.indexOf(result) - 1] || null;
    const delta = prev ? result.score.score - prev.score.score : null;
    const counts = CT.engines.risk.countBySeverity(result.findings);

    return h('div.stack.gap12', [
      S.simulatedBanner(result),
      h('div.card', [
        h('div.row.gap10', [
          h('span', { style: { color: 'var(--ok)', display: 'flex' } }, icon('shieldCheck')),
          h('span.grow', [
            h('div', { style: { 'font-weight': '650' } }, 'Assessment #' + String(result.number).padStart(3, '0') + ' complete'),
            h('div.tiny.muted', CT.util.fmtClock(result.durationMs) + ' · ' + result.profileName)
          ])
        ]),
        h('dl.mt12', [
          CT.dom.kv('Scope', result.scopeLabel, { mono: true }),
          CT.dom.kv('Assets', String(result.stats.hosts)),
          CT.dom.kv('Services', String(result.stats.services)),
          CT.dom.kv('Findings', String(result.stats.findings)),
          CT.dom.kv('Security score', h('span.row.gap6', { style: { 'justify-content': 'flex-end' } }, [
            h('span', { style: { 'font-weight': '700' } }, result.score.score + ' / 100'),
            delta !== null && delta !== 0
              ? h('span.pill.' + (delta > 0 ? 'ok' : 'high'), (delta > 0 ? '+' : '') + delta)
              : null
          ]))
        ]),
        result.findings.length ? h('div.mt12', S.severityBar(counts, result.findings.length)) : null
      ]),
      h('div.btn-grid', [
        h('button.btn.primary', { type: 'button', onClick: () => { lastResult = null; S.navigate('#/findings'); } }, [icon('alert'), 'Review findings']),
        h('button.btn', { type: 'button', onClick: () => { lastResult = null; S.navigate('#/reports'); } }, [icon('report'), 'Generate report']),
        h('button.btn', { type: 'button', onClick: () => { lastResult = null; S.navigate('#/compare'); } }, [icon('compare'), 'Compare']),
        h('button.btn', { type: 'button', onClick: () => { lastResult = null; S.navigate('#/dashboard'); } }, [icon('dashboard'), 'Dashboard'])
      ]),
      h('button.btn.ghost.block', { type: 'button', onClick: () => { lastResult = null; resetWizard(); S.render(); } },
        [icon('refresh'), 'Run another assessment'])
    ]);
  }

  /* ==========================================================================
     ERROR STATES
     ======================================================================= */
  function errorNotice(err) {
    const actions = {
      capability: { label: 'Open Tools', onClick: () => S.navigate('#/tools') },
      empty: { label: 'Adjust scope', onClick: () => { lastError = null; wiz.step = 0; S.render(); } },
      scope: { label: 'Edit scope', onClick: () => { lastError = null; wiz.step = 0; S.render(); } },
      unauthorized: { label: 'Review authorization', onClick: () => { lastError = null; wiz.step = 2; S.render(); } },
      cancelled: { label: 'Start again', onClick: () => { lastError = null; resetWizard(); S.render(); } },
      permission: { label: 'Open Settings', onClick: () => S.navigate('#/settings') }
    };
    const a = actions[err.code] || { label: 'Dismiss', onClick: () => { lastError = null; S.render(); } };
    return h('div.notice.err', [
      icon('alertCircle'),
      h('div.grow', [
        h('strong', err.title),
        h('span', err.body),
        h('div.mt8', h('button.btn.sm', { type: 'button', onClick: a.onClick }, a.label))
      ])
    ]);
  }

  CT.ui.scanReset = function () { lastResult = null; lastError = null; resetWizard(); };
})();
