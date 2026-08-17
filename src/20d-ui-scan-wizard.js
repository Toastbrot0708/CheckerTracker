/* ============================================================================
   MODULE: CT.ui.routes.scan — the assessment wizard
   ========================================================================= */
(function () {
  'use strict';
  const h = CT.dom.h, icon = CT.dom.icon, S = CT.ui.shell;

  const SCOPE_MODES = [
    { id: 'current', label: 'This network' },
    { id: 'cidr', label: 'Custom CIDR' },
    { id: 'host', label: 'Single host' },
    { id: 'saved', label: 'Saved scope' }
  ];

  let wiz = null, lastError = null, lastResult = null;

  function detectedSubnet() {
    const net = CT.live.network();
    return (net && net.subnet) || '';
  }

  function reset() {
    wiz = {
      step: 0, mode: 'current', scopeText: detectedSubnet(),
      savedId: null, profileId: 'full', authorized: false, windowHours: 24
    };
  }

  function validate() {
    const text = wiz.scopeText;
    if (!text || !text.trim()) return { ok: false, error: 'No scope defined.' };
    try { return { ok: true, scope: CT.net.parseScope(text) }; }
    catch (e) { return { ok: false, error: e.message }; }
  }

  CT.ui.routes.scan = {
    tab: 'scan',
    title: () => 'Scan Center',
    subtitle: () => {
      const r = CT.engines.scanner.currentRun();
      if (r) return 'Assessment running · ' + r.progress + '%';
      return CT.live.online ? 'Live assessment' : 'Scanner service offline';
    },
    render() {
      const run = CT.engines.scanner.currentRun();
      if (run) return CT.ui.scanRun.progressView(run);
      if (lastResult) return CT.ui.scanRun.resultView(lastResult, () => { lastResult = null; });
      if (!wiz) reset();
      if (!wiz.scopeText && wiz.mode === 'current') wiz.scopeText = detectedSubnet();

      const steps = ['Scope', 'Scan type', 'Authorize'];
      return h('div.stack.gap12', [
        !CT.live.online ? offlineNotice() : null,
        h('div.steps', { role: 'progressbar', 'aria-valuemin': '1', 'aria-valuemax': '3',
          'aria-valuenow': String(wiz.step + 1),
          'aria-label': 'Step ' + (wiz.step + 1) + ' of 3: ' + steps[wiz.step] },
          steps.map((s, i) => h('span.step-dot', {
            dataset: { state: i < wiz.step ? 'done' : i === wiz.step ? 'active' : 'pending' } }))),
        h('div.row.gap8', [
          h('span.tiny.muted', 'Step ' + (wiz.step + 1) + ' of 3'),
          h('span.grow'),
          h('span.tiny', { style: { 'font-weight': '650' } }, steps[wiz.step])
        ]),
        lastError ? errorNotice(lastError) : null,
        wiz.step === 0 ? stepScope() : wiz.step === 1 ? stepProfile() : stepAuthorize(),
        footer()
      ]);
    }
  };

  function offlineNotice() {
    return h('div.notice.warn', [icon('alertCircle'), h('div.grow', [
      h('strong', 'Scanner service not reachable'),
      h('span', 'Active scanning needs the local service. Start it with "node server/checkertracker.js" on a machine in the network you want to assess, then open the URL it prints. The offline tools work regardless.'),
      h('div.mt8', h('button.btn.sm', { type: 'button',
        onClick: () => CT.live.probe().then(() => { CT.engines.capabilities.refresh(); S.render(); }) },
        [icon('refresh'), 'Check again']))
    ])]);
  }

  function footer() {
    const v = validate();
    const canNext = wiz.step === 0 ? v.ok : true;
    return h('div.wizard-foot', h('div.btn-row', [
      wiz.step > 0 ? h('button.btn.ghost', { type: 'button',
        onClick: () => { wiz.step--; S.render(); } }, [icon('chevronLeft'), 'Back']) : null,
      wiz.step < 2
        ? h('button.btn.primary', { type: 'button', disabled: !canNext,
            onClick: () => { if (canNext) { wiz.step++; lastError = null; S.render(); } } },
            ['Continue', icon('chevronRight')])
        : h('button.btn.primary', { type: 'button',
            disabled: !wiz.authorized || !CT.live.online,
            'aria-disabled': (wiz.authorized && CT.live.online) ? null : 'true',
            onClick: startScan }, [icon('play'), 'Start assessment'])
    ]));
  }

  function stepScope() {
    const v = validate();
    const net = CT.live.network();
    const box = h('div.stack.gap12');

    box.appendChild(h('div.card', [
      h('div.card-head', [icon('scope'), h('h3', 'Define the authorized scope')]),
      h('p.small.dim.mb12', 'Probes are constrained to exactly these addresses. Nothing outside the scope is contacted.'),
      h('div.segmented.mb12', { role: 'group', 'aria-label': 'Scope type' }, SCOPE_MODES.map((m) =>
        h('button', { type: 'button', 'aria-pressed': wiz.mode === m.id ? 'true' : 'false',
          onClick: () => {
            wiz.mode = m.id;
            if (m.id === 'current') wiz.scopeText = detectedSubnet();
            if (m.id === 'cidr') wiz.scopeText = detectedSubnet() || '192.168.1.0/24';
            if (m.id === 'host') wiz.scopeText = (net && net.gateway) || '';
            if (m.id === 'saved' && CT.store.state.savedScopes.length) {
              wiz.savedId = CT.store.state.savedScopes[0].id;
              wiz.scopeText = CT.store.state.savedScopes[0].value;
            }
            S.render();
          } }, m.label))),
      scopeInput(net)
    ]));

    if (v.ok) {
      const first = v.scope.entries[0];
      box.appendChild(h('div.card', { style: { 'border-color': 'var(--accent-line)', background: 'var(--accent-dim)' } }, [
        h('div.section-label', { style: { color: 'var(--accent-2)' } }, 'Authorized scope'),
        h('div.mono', { style: { 'font-size': '1.05em', 'font-weight': '650', 'word-break': 'break-word' } },
          v.scope.label.length > 90 ? v.scope.label.slice(0, 90) + ' …' : v.scope.label),
        h('div.tiny.muted.mt6', CT.util.fmtNum(v.scope.totalHosts) + ' addresses in scope'),
        first && first.info ? h('dl.mt12', [
          CT.dom.kv('Network', first.info.network, { mono: true }),
          CT.dom.kv('Netmask', first.info.netmask, { mono: true }),
          CT.dom.kv('Host range', first.info.rangeLabel, { mono: true }),
          CT.dom.kv('Usable hosts', CT.util.fmtNum(first.info.usableHosts), { mono: true })
        ]) : null,
        h('div.notice.accent.mt12', [icon('clock'), h('div.grow', [
          h('strong', wiz.windowHours + '-hour authorization window'),
          h('span', 'Confirmation applies to this scope only and lapses automatically.')
        ])]),
        h('button.btn.sm.ghost.mt12', { type: 'button',
          onClick: () => S.prompt({ title: 'Save scope', label: 'Name', placeholder: 'e.g. Home LAN' })
            .then((name) => { if (name) { CT.store.saveScope(name, v.scope.label); S.toast('Scope saved', 'ok'); } })
        }, [icon('plus'), 'Save this scope'])
      ]));
    } else {
      box.appendChild(CT.dom.notice('err', 'Scope invalid', v.error));
    }
    return box;
  }

  function scopeInput(net) {
    if (wiz.mode === 'saved') {
      const saved = CT.store.state.savedScopes;
      if (!saved.length) return CT.dom.notice('warn', 'No saved scopes', 'Define a CIDR scope and save it for reuse.');
      return h('label.field', [
        h('span.lbl', 'Saved scope'),
        h('select', { 'aria-label': 'Saved scope', on: { change: function () {
          wiz.savedId = this.value;
          const s = saved.find((x) => x.id === this.value);
          if (s) wiz.scopeText = s.value;
          S.render();
        } } }, saved.map((s) => h('option', { value: s.id, selected: wiz.savedId === s.id ? true : null },
          s.name + ' — ' + s.value)))
      ]);
    }
    return h('label.field', [
      h('span.lbl', wiz.mode === 'host' ? 'Host address'
        : wiz.mode === 'cidr' ? 'CIDR block' : 'Detected network'),
      h('input', { type: 'text', value: wiz.scopeText, spellcheck: 'false',
        autocapitalize: 'off', autocorrect: 'off', 'aria-label': 'Scope',
        readonly: wiz.mode === 'current' ? true : null,
        placeholder: '192.168.1.0/24',
        on: { input: CT.util.debounce(function () { wiz.scopeText = this.value; S.render(); }, 350) } }),
      h('span.hint', wiz.mode === 'current'
        ? (net && net.subnet
            ? 'Read from ' + (net.iface || 'the active interface') + ' on the machine running the scanner service.'
            : 'No interface detected. Start the scanner service, or enter a block manually.')
        : 'IPv4 addresses or CIDR blocks (/16 or narrower). Separate multiple entries with commas.')
    ]);
  }

  function stepProfile() {
    return h('div.stack.gap12', [
      h('div', [
        CT.dom.sectionLabel('Scan profile'),
        h('div', CT.scanProfiles.PROFILES.map((p) => h('button.profile-card', {
          type: 'button', 'aria-pressed': wiz.profileId === p.id ? 'true' : 'false',
          onClick: () => { wiz.profileId = p.id; S.render(); }
        }, [
          h('span.pico', icon(p.icon)),
          h('span.grow', [
            h('span.row.gap6', [h('span.ptitle', p.name), h('span.tag', p.intensity)]),
            h('span.pdesc', p.description),
            h('span.pmeta', p.stages.map((s) => CT.scanProfiles.STAGE_LABEL[s]).join(' → '))
          ])
        ])))
      ]),
      h('div.notice', [icon('shield'), h('div.grow', [
        h('strong', 'What no profile does'),
        h('span', 'None of these attempt authentication, submit credentials, exercise a vulnerability, or change anything on a target. Connections complete normally and close, so the activity is plainly visible in your own logs.')
      ])])
    ]);
  }

  function stepAuthorize() {
    const v = validate();
    const profile = CT.scanProfiles.byId(wiz.profileId);

    return h('div.stack.gap12', [
      h('div.card', [
        h('div.card-head', [icon('shieldCheck'), h('h3', 'Assessment summary')]),
        h('dl', [
          CT.dom.kv('Scope', v.ok ? v.scope.label : '—', { mono: true }),
          CT.dom.kv('Addresses', v.ok ? CT.util.fmtNum(v.scope.totalHosts) : '—'),
          CT.dom.kv('Profile', profile.name),
          CT.dom.kv('Intensity', profile.intensity),
          CT.dom.kv('Execution', CT.live.online ? 'Live probes from the scanner service' : 'unavailable')
        ])
      ]),
      h('div.card', [
        h('div.card-head', [icon('lock'), h('h3', 'Authorization')]),
        h('p.small.dim.mb12', 'Active testing without the system owner\'s permission is unlawful in most jurisdictions. This confirmation is recorded in the audit log with the scope and timestamp, and the service refuses any run that does not carry it.'),
        h('label.check', [
          h('input', { type: 'checkbox', checked: wiz.authorized ? true : null,
            on: { change: function () { wiz.authorized = this.checked; S.render(); } } }),
          h('span.box', icon('check', { weight: '3' })),
          h('span.txt', 'I confirm that I am authorized to test these systems.')
        ]),
        !wiz.authorized ? h('p.tiny.muted', { style: { margin: '8px 0 0' } },
          'Active scans cannot start until this is confirmed.') : null
      ])
    ]);
  }

  function startScan() {
    lastError = null;
    const v = validate();
    if (!v.ok) { lastError = { code: 'scope', title: 'Scope invalid', body: v.error }; S.render(); return; }

    CT.store.grantAuthorization(v.scope.label, wiz.windowHours);
    const prev = CT.store.currentAssessment();

    let run;
    try {
      run = CT.engines.scanner.start({
        scopeText: wiz.scopeText,
        profileId: wiz.profileId,
        authorized: wiz.authorized,
        authorization: CT.store.state.authorization,
        baseline: prev ? prev.assets : null,
        baselineAt: prev ? prev.endedAt : null
      });
    } catch (e) {
      const def = CT.scanProfiles.ERRORS[e.code] || { title: 'Scan could not start' };
      lastError = { code: e.code || 'error', title: def.title, body: e.message };
      S.render();
      return;
    }

    run.on('done', (result) => {
      if (!result.assets.length) {
        lastError = { code: 'empty', title: CT.scanProfiles.ERRORS.empty.title,
                      body: CT.scanProfiles.ERRORS.empty.body };
        lastResult = null;
      } else {
        lastResult = CT.store.saveAssessment(result);
      }
      S.render();
    });
    run.on('error', (err) => { lastError = err; lastResult = null; S.render(); });

    S.render();
  }

  function errorNotice(err) {
    const actions = {
      capability: { label: 'Check for the service', onClick: () =>
        CT.live.probe().then(() => { CT.engines.capabilities.refresh(); lastError = null; S.render(); }) },
      empty: { label: 'Adjust scope', onClick: () => { lastError = null; wiz.step = 0; S.render(); } },
      scope: { label: 'Edit scope', onClick: () => { lastError = null; wiz.step = 0; S.render(); } },
      unauthorized: { label: 'Review authorization', onClick: () => { lastError = null; wiz.step = 2; S.render(); } },
      cancelled: { label: 'Start again', onClick: () => { lastError = null; reset(); S.render(); } }
    };
    const a = actions[err.code] || { label: 'Dismiss', onClick: () => { lastError = null; S.render(); } };
    return h('div.notice.err', [icon('alertCircle'), h('div.grow', [
      h('strong', err.title),
      h('span', err.body),
      h('div.mt8', h('button.btn.sm', { type: 'button', onClick: a.onClick }, a.label))
    ])]);
  }

  CT.ui.scanReset = function () { lastResult = null; lastError = null; reset(); };
})();
