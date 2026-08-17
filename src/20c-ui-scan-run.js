/* ============================================================================
   MODULE: CT.ui.scanRun — live progress, result and error views
   ========================================================================= */
CT.ui.scanRun = (function () {
  'use strict';
  const h = CT.dom.h, icon = CT.dom.icon, S = CT.ui.shell;

  /** Derived from the run, never asserted, so a real sweep is never mislabelled. */
  function runBanner(run) {
    if (run.simulated) {
      return h('div.demo-banner', [icon('alert'), h('div.grow', [
        h('strong', 'SIMULATED ASSESSMENT'), ' — no packet is sent to any network.'])]);
    }
    return h('div.notice.accent', [icon('radar'), h('div.grow', [
      h('strong', 'LIVE ASSESSMENT'),
      h('span', 'Probing ' + run.scopeLabel + ' from the scanner service. Only addresses inside this scope are contacted.')
    ])]);
  }

  function progressView(run) {
    // The screen can be rebuilt while the run continues. Drop the previous
    // rendering's listeners; the durable channel keeps the result handler.
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
        s.state === 'skipped' ? h('span.stage-meta', 'not in profile')
          : s.meta ? h('span.stage-meta', s.meta) : null
      ])));
    }

    function paintControls() {
      CT.dom.clear(controls);
      if (run.state === 'running') {
        controls.appendChild(h('button.btn.ghost', { type: 'button', onClick: () => run.pause() },
          [icon('pause'), 'Pause']));
      } else if (run.state === 'paused') {
        controls.appendChild(h('button.btn.primary', { type: 'button', onClick: () => run.resume() },
          [icon('play'), 'Resume']));
      }
      controls.appendChild(h('button.btn.danger', {
        type: 'button',
        onClick: () => S.confirm({
          title: 'Cancel assessment?', danger: true, confirmLabel: 'Cancel scan',
          body: 'The sweep stops immediately and no partial results are saved.'
        }).then((ok) => { if (ok) { run.cancel(); S.render(); } })
      }, [icon('stop'), 'Cancel']));
    }

    function appendLog(entry) {
      logBox.appendChild(h('div', [
        h('span.ts', CT.util.fmtTime(entry.ts) + '  '),
        h('span' + (entry.kind === 'hit' ? '.hit' : entry.kind === 'fnd' ? '.fnd' : ''), entry.text)
      ]));
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
      runBanner(run),
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
          h('span.tiny.muted', CT.util.plural(run.counters.hostsTotal, 'address') + ' in scope')
        ])
      ]),
      h('div.metric-grid.c2', [
        h('div.metric', [elapsedEl, h('div.l', 'Elapsed')]),
        h('div.metric', [hostsEl, h('div.l', 'Hosts responding')])
      ]),
      h('div.metric-grid.c2', [
        h('div.metric', [svcEl, h('div.l', 'Services identified')]),
        h('div.metric', [findEl, h('div.l', 'Findings detected')])
      ]),
      h('div.card', [h('div.card-head', [icon('list'), h('h3', 'Stages')]), stagesBox]),
      h('div.card', [h('div.card-head', [icon('terminal'), h('h3', 'Live log')]), logBox]),
      controls
    ]);
  }

  function resultView(result, onReset) {
    const list = CT.store.state.assessments;
    const prev = list[list.indexOf(result) - 1] || null;
    const delta = prev ? result.score.score - prev.score.score : null;
    const counts = CT.engines.risk.countBySeverity(result.findings);
    const attention = (counts.critical || 0) + (counts.high || 0);

    return h('div.stack.gap12', [
      S.simulatedBanner(result),
      h('div.card', [
        h('div.row.gap10', [
          h('span', { style: { color: 'var(--ok)', display: 'flex' } }, icon('shieldCheck')),
          h('span.grow', [
            h('div', { style: { 'font-weight': '650' } },
              'Assessment #' + String(result.number).padStart(3, '0') + ' complete'),
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
              ? h('span.pill.' + (delta > 0 ? 'ok' : 'high'), (delta > 0 ? '+' : '') + delta) : null
          ]))
        ]),
        result.findings.length ? h('div.mt12', S.severityBar(counts, result.findings.length)) : null,
        attention ? h('div.notice.err.mt12', [icon('alert'), h('div.grow', [
          h('strong', CT.util.plural(attention, 'finding') + ' need attention'),
          h('span', 'Rated critical or high. Open Findings to see what was observed and how to correct it.')
        ])]) : null
      ]),
      h('div.btn-grid', [
        h('button.btn.primary', { type: 'button', onClick: () => { onReset(); S.navigate('#/findings'); } },
          [icon('alert'), 'Review findings']),
        h('button.btn', { type: 'button', onClick: () => { onReset(); S.navigate('#/reports'); } },
          [icon('report'), 'Generate report']),
        h('button.btn', { type: 'button', onClick: () => { onReset(); S.navigate('#/compare'); } },
          [icon('compare'), 'Compare']),
        h('button.btn', { type: 'button', onClick: () => { onReset(); S.navigate('#/dashboard'); } },
          [icon('dashboard'), 'Dashboard'])
      ])
    ]);
  }

  return { progressView, resultView, runBanner };
})();
