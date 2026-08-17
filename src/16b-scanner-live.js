/* ============================================================================
   MODULE: CT.engines.scanner — drives a real sweep via the scanner service
   ---------------------------------------------------------------------------
   If the service is not reachable, a scan cannot start. Nothing here
   substitutes a result.
   ========================================================================= */
CT.engines.scanner = (function () {
  'use strict';

  const P = CT.scanProfiles;
  let current = null;

  function emit(run, type, payload) {
    const fire = (fn) => { try { fn(payload); } catch (e) { console.error('[scanner]', e); } };
    (run.listeners[type] || []).forEach(fire);
    (run.viewListeners[type] || []).forEach(fire);
  }

  function log(run, text, kind) {
    const entry = { ts: Date.now(), text, kind: kind || 'info' };
    run.log.push(entry);
    if (run.log.length > 600) run.log.shift();
    emit(run, 'log', entry);
  }

  function start(cfg) {
    if (current && current.state === 'running') throw new Error('An assessment is already running.');
    if (!cfg.authorized) { const e = new Error(P.ERRORS.unauthorized.body); e.code = 'unauthorized'; throw e; }
    if (!CT.engines.capabilities.canRunLiveScan()) {
      const e = new Error(P.ERRORS.capability.body); e.code = 'capability'; throw e;
    }

    let scope;
    try { scope = CT.net.parseScope(cfg.scopeText); }
    catch (err) { const e = new Error(err.message); e.code = 'scope'; throw e; }

    const profile = P.byId(cfg.profileId);
    const network = CT.live.network();

    const run = {
      id: 'run-' + Date.now().toString(36),
      state: 'running',
      scope, scopeLabel: scope.label,
      profile, profileId: profile.id,
      environmentId: 'live',
      environmentName: network && network.name ? network.name : 'this network',
      network,
      simulated: false,
      mode: 'live',
      authorization: cfg.authorization || null,
      startedAt: Date.now(),
      endedAt: null, elapsedMs: 0, progress: 0,
      listeners: {}, viewListeners: {}, log: [],
      stages: P.ALL_STAGES.map((id) => ({
        id, label: P.STAGE_LABEL[id],
        state: profile.stages.indexOf(id) === -1 ? 'skipped' : 'pending',
        meta: null
      })),
      counters: { hosts: 0, hostsTotal: scope.totalHosts, services: 0, findings: 0 },
      _baseline: cfg.baseline || null,
      _baselineAt: cfg.baselineAt || null,
      _source: null,
      on(t, fn) { (this.listeners[t] = this.listeners[t] || []).push(fn); return this; },
      onView(t, fn) { (this.viewListeners[t] = this.viewListeners[t] || []).push(fn); return this; },
      clearViewListeners() { this.viewListeners = {}; },
      pause() { if (this._runId) CT.live.control(this._runId, 'pause'); },
      resume() { if (this._runId) CT.live.control(this._runId, 'resume'); },
      cancel() {
        if (this._runId) CT.live.control(this._runId, 'cancel').catch(() => {});
        if (this._source) this._source.close();
        this.state = 'cancelled';
        if (current === this) current = null;
        emit(this, 'error', { code: 'cancelled', title: P.ERRORS.cancelled.title, body: P.ERRORS.cancelled.body });
      }
    };

    current = run;
    log(run, 'Requesting sweep of ' + scope.label + ' from the scanner service');

    const clock = setInterval(() => {
      if (run.state !== 'running') return;
      run.elapsedMs = Date.now() - run.startedAt;
      emit(run, 'progress', run);
    }, 500);
    run._clock = clock;

    CT.live.startScan({
      authorized: true,
      scope: cfg.scopeText,
      depth: profile.depth,
      stages: profile.stages
    }).then((res) => {
      run._runId = res.runId;
      run.counters.hostsTotal = res.scope.total;
      run._source = CT.live.stream(res.runId, handlers(run));
    }).catch((err) => {
      clearInterval(clock);
      run.state = 'error';
      if (current === run) current = null;
      const def = P.ERRORS[err.code] || { title: 'Scan could not start' };
      emit(run, 'error', { code: err.code || 'error', title: def.title, body: err.message });
    });

    return run;
  }

  function handlers(run) {
    return {
      progress(p) {
        run.progress = Math.min(99, p.progress);
        run.counters.hosts = p.counters.hosts;
        run.counters.services = p.counters.services;
        run.elapsedMs = Date.now() - run.startedAt;
        emit(run, 'progress', run);
      },
      stage(s) {
        const stage = run.stages.find((x) => x.id === s.id);
        if (!stage) return;
        stage.state = s.state;
        stage.meta = s.meta;
        emit(run, 'stage', run.stages);
      },
      log(entry) { run.log.push(entry); emit(run, 'log', entry); },
      state(s) { run.state = s; emit(run, 'state', run); },
      done(result) { complete(run, result); },
      failed(err) {
        clearInterval(run._clock);
        run.state = err.code === 'cancelled' ? 'cancelled' : 'error';
        if (current === run) current = null;
        const def = P.ERRORS[err.code] || { title: 'Assessment failed' };
        emit(run, 'error', { code: err.code, title: def.title, body: err.message });
      }
    };
  }

  /** Analysis and scoring run here, on this device, over the real inventory. */
  function complete(run, payload) {
    clearInterval(run._clock);
    run.progress = 100;
    run.state = 'done';
    run.endedAt = Date.now();
    run.elapsedMs = run.endedAt - run.startedAt;

    const assets = CT.live.hydrate(payload.assets, run._baseline);
    run.stages.filter((s) => s.id === 'analyze' || s.id === 'score')
      .forEach((s) => { if (s.state !== 'skipped') s.state = 'done'; });

    let findings = CT.engines.analyzer.analyze(assets, {
      network: run.network, at: run.endedAt, simulated: false,
      baseline: run._baseline, baselineAt: run._baselineAt
    });
    if (run.profile.rules) {
      findings = findings.filter((f) => run.profile.rules.some((p) => f.ruleId.indexOf(p) === 0));
    }

    const score = CT.engines.risk.scoreEnvironment(assets, findings);
    run.counters.findings = findings.length;
    run.counters.services = assets.reduce((n, a) => n + (a.services || []).length, 0);

    log(run, 'Assessment complete — ' + assets.length + ' assets, ' + run.counters.services +
      ' services, ' + findings.length + ' findings, score ' + score.score + '/100');

    const result = {
      id: run.id,
      startedAt: run.startedAt, endedAt: run.endedAt, durationMs: run.elapsedMs,
      scopeLabel: run.scopeLabel, scopeRaw: run.scope.raw,
      profileId: run.profile.id, profileName: run.profile.name,
      environmentId: 'live', environmentName: run.environmentName,
      network: run.network,
      mode: 'live', simulated: false,
      authorization: run.authorization,
      assets, findings, score,
      stats: { hosts: assets.length, services: run.counters.services, findings: findings.length },
      log: run.log.slice()
    };

    run.result = result;
    emit(run, 'stage', run.stages);
    emit(run, 'progress', run);
    emit(run, 'state', run);
    emit(run, 'done', result);
    if (current === run) current = null;
  }

  return {
    PROFILES: P.PROFILES, STAGE_LABEL: P.STAGE_LABEL, ALL_STAGES: P.ALL_STAGES, ERRORS: P.ERRORS,
    profileById: P.byId,
    start, currentRun: () => current
  };
})();
