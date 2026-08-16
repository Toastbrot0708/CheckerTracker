/* ============================================================================
   MODULE: CT.engines.scanner — scan orchestration
   ---------------------------------------------------------------------------
   Enforces the authorization gate, drives the stage pipeline, reports live
   progress, and hands back a completed assessment.

   In this web runtime the discovery and service-probing stages cannot be
   performed for real (see CT.engines.capabilities). A run therefore executes
   against a declared demo environment and is permanently stamped
   mode = 'simulated'. That stamp travels with the assessment into history,
   comparisons, reports and every export.
   ========================================================================= */
CT.engines.scanner = (function () {
  'use strict';

  const STAGE_LABEL = {
    authorize: 'Validating authorization and scope',
    discover: 'Discovering hosts',
    identify: 'Identifying services',
    metadata: 'Collecting metadata',
    tls: 'Checking TLS configuration',
    headers: 'Reviewing security headers',
    analyze: 'Analyzing findings',
    score: 'Generating risk score'
  };

  const PROFILES = [
    { id: 'passive', name: 'Passive Discovery', icon: 'radar', intensity: 'Passive',
      description: 'Records what the segment already broadcasts. No probes are sent to any host.',
      stages: ['authorize', 'discover', 'analyze', 'score'],
      depth: 'passive', rules: ['CT-INV-', 'CT-NET-009'] },
    { id: 'discovery', name: 'Network Discovery', icon: 'crosshair', intensity: 'Light',
      description: 'Identifies which hosts are reachable inside the authorized scope.',
      stages: ['authorize', 'discover', 'metadata', 'analyze', 'score'],
      depth: 'hosts', rules: ['CT-INV-', 'CT-CFG-004'] },
    { id: 'services', name: 'Service Inventory', icon: 'layers', intensity: 'Moderate',
      description: 'Enumerates reachable network services and their basic properties.',
      stages: ['authorize', 'discover', 'identify', 'metadata', 'analyze', 'score'],
      depth: 'services', rules: ['CT-NET-', 'CT-INV-', 'CT-CFG-003', 'CT-CFG-004'] },
    { id: 'config', name: 'Configuration Audit', icon: 'shieldCheck', intensity: 'Moderate',
      description: 'Reviews defensively relevant misconfigurations across discovered services.',
      stages: ['authorize', 'discover', 'identify', 'metadata', 'analyze', 'score'],
      depth: 'services', rules: ['CT-CFG-', 'CT-NET-', 'CT-INV-'] },
    { id: 'tls', name: 'TLS / Certificate Audit', icon: 'certificate', intensity: 'Light',
      description: 'Validity, expiry, hostname match, chain, protocol versions and key strength.',
      stages: ['authorize', 'discover', 'identify', 'tls', 'analyze', 'score'],
      depth: 'services', rules: ['CT-TLS-'] },
    { id: 'web', name: 'Web Security Review', icon: 'globe', intensity: 'Moderate',
      description: 'For explicitly authorized web systems: reachability, security headers, TLS, cookie attributes, redirect behaviour and server banners. No vulnerability is exercised.',
      stages: ['authorize', 'discover', 'identify', 'tls', 'headers', 'analyze', 'score'],
      depth: 'services', rules: ['CT-WEB-', 'CT-TLS-'] },
    { id: 'full', name: 'Full Assessment', icon: 'shield', intensity: 'Comprehensive',
      description: 'Combines every check above into one structured assessment.',
      stages: ['authorize', 'discover', 'identify', 'metadata', 'tls', 'headers', 'analyze', 'score'],
      depth: 'services', rules: null }
  ];

  const profileById = (id) => PROFILES.find((p) => p.id === id) || PROFILES[PROFILES.length - 1];

  const ALL_STAGES = ['authorize', 'discover', 'identify', 'metadata', 'tls', 'headers', 'analyze', 'score'];

  /* -- Errors surfaced to the user with a concrete next step --------------- */
  const ERRORS = {
    unauthorized: { title: 'Authorization required',
      body: 'Active checks cannot start until you confirm that you are authorized to test the systems in scope.' },
    scope: { title: 'Scope invalid', body: null },
    capability: { title: 'Scan unavailable',
      body: 'Host discovery and service probing require raw network access, which this runtime does not provide. Run an assessment against a demo environment instead, or use the Tools section for the checks that work here for real.' },
    empty: { title: 'No hosts responded',
      body: 'No device in the selected environment falls inside the declared scope. Widen the scope or choose a different environment.' },
    cancelled: { title: 'Scan cancelled', body: 'The assessment was stopped before completion. No partial results were saved.' }
  };

  let current = null;

  /**
   * Two listener channels. `listeners` belong to whoever started the run and
   * must survive the progress screen being rebuilt; `viewListeners` belong to
   * the current rendering of that screen and are discarded when it is rebuilt.
   */
  function emit(run, type, payload) {
    const fire = (fn) => {
      try { fn(payload); } catch (e) { console.error('[scanner] listener error', e); }
    };
    (run.listeners[type] || []).forEach(fire);
    (run.viewListeners[type] || []).forEach(fire);
  }

  /**
   * Begin an assessment.
   * @param {object} cfg { scopeText, profileId, environmentId, authorized, authorization, baseline }
   */
  function start(cfg) {
    if (current && current.state === 'running') throw new Error('An assessment is already running.');

    if (!cfg.authorized) { const e = new Error(ERRORS.unauthorized.body); e.code = 'unauthorized'; throw e; }

    let scope;
    try { scope = CT.net.parseScope(cfg.scopeText); }
    catch (err) { const e = new Error(err.message); e.code = 'scope'; throw e; }

    const profile = profileById(cfg.profileId);
    const live = !!cfg.live;
    if (live && !CT.engines.capabilities.canRunLiveScan()) {
      const e = new Error(ERRORS.capability.body); e.code = 'capability'; throw e;
    }

    const env = CT.demo.build(cfg.environmentId || 'corp-lab');
    const targets = env.assets.filter((a) => scope.contains(a.ip));

    const run = {
      id: CT.util.uid('run'),
      state: 'running',
      scope, scopeLabel: scope.label, profile, profileId: profile.id,
      environmentId: cfg.environmentId || 'corp-lab',
      environmentName: env.network.name,
      network: env.network,
      simulated: true,
      mode: 'simulated',
      authorization: cfg.authorization || null,
      startedAt: Date.now(),
      endedAt: null,
      elapsedMs: 0,
      progress: 0,
      listeners: {},
      viewListeners: {},
      log: [],
      stages: ALL_STAGES.map((id) => ({
        id, label: STAGE_LABEL[id],
        state: profile.stages.indexOf(id) === -1 ? 'skipped' : 'pending',
        meta: null
      })),
      counters: { hosts: 0, hostsTotal: targets.length, services: 0, findings: 0 },
      _targets: targets,
      _env: env,
      _baseline: cfg.baseline || null,
      _baselineAt: cfg.baselineAt || null,
      _discovered: [],
      on(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); return this; },
      onView(type, fn) { (this.viewListeners[type] = this.viewListeners[type] || []).push(fn); return this; },
      clearViewListeners() { this.viewListeners = {}; },
      pause() { if (this.state === 'running') { this.state = 'paused'; log(this, 'Assessment paused by operator', 'info'); emit(this, 'state', this); } },
      resume() { if (this.state === 'paused') { this.state = 'running'; log(this, 'Assessment resumed', 'info'); emit(this, 'state', this); } },
      cancel() {
        if (this.state === 'done' || this.state === 'error') return;
        this.state = 'cancelled';
        clearInterval(this._timer);
        log(this, 'Assessment cancelled by operator', 'warn');
        emit(this, 'state', this);
        emit(this, 'error', { code: 'cancelled', title: ERRORS.cancelled.title, body: ERRORS.cancelled.body });
        if (current === this) current = null;
      }
    };

    current = run;
    buildPlan(run);
    log(run, 'Authorization confirmed for scope ' + scope.label, 'info');
    log(run, 'Profile: ' + profile.name + ' (' + profile.intensity + ')', 'info');
    log(run, 'Runtime cannot perform raw network probing — executing against demo environment "' + env.network.name + '"', 'warn');

    run._timer = setInterval(() => tick(run), run._interval);
    return run;
  }

  function log(run, text, kind) {
    const entry = { ts: Date.now(), text, kind: kind || 'info' };
    run.log.push(entry);
    if (run.log.length > 400) run.log.shift();
    emit(run, 'log', entry);
  }

  /* Build the tick plan: each unit of work is one visible step. */
  function buildPlan(run) {
    const t = run._targets;
    const active = run.profile.stages;
    const plan = [];
    const addStage = (id, units) => {
      if (active.indexOf(id) === -1) return;
      plan.push({ stage: id, units });
    };
    addStage('authorize', 5);
    addStage('discover', Math.max(6, Math.min(t.length, 260)));
    addStage('identify', Math.max(6, Math.min(t.reduce((a, x) => a + (x.services || []).length, 0), 300)));
    addStage('metadata', Math.max(4, Math.min(t.length, 120)));
    addStage('tls', Math.max(3, t.filter((x) => x.tls).length * 3));
    addStage('headers', Math.max(3, t.filter((x) => x.http).length * 3));
    addStage('analyze', 10);
    addStage('score', 6);
    run._plan = plan;
    run._planTotal = plan.reduce((a, p) => a + p.units, 0);
    run._done = 0;
    run._stageIdx = 0;
    run._stageUnit = 0;

    // Precompute the work lists once rather than rebuilding them every tick.
    run._allServices = [];
    t.forEach((a) => (a.services || []).forEach((s) => run._allServices.push({ a, s })));
    run._tlsHosts = t.filter((a) => a.tls);
    run._httpHosts = t.filter((a) => a.http);

    // Keep wall-clock duration sane across environment sizes: an 18-asset lab
    // runs in roughly nine seconds, a 520-asset one in roughly fifteen.
    const targetMs = 8000 + run._planTotal * 8;
    run._interval = CT.util.clamp(Math.round(targetMs / Math.max(1, run._planTotal)), 12, 90);
  }

  function tick(run) {
    if (run.state !== 'running') return;
    run.elapsedMs = Date.now() - run.startedAt;

    const plan = run._plan;
    if (run._stageIdx >= plan.length) { finish(run); return; }

    const step = plan[run._stageIdx];
    const stage = run.stages.find((s) => s.id === step.stage);
    if (run._stageUnit === 0) {
      stage.state = 'active';
      emit(run, 'stage', run.stages);
      log(run, STAGE_LABEL[step.stage] + '…', 'info');
    }

    doUnit(run, step.stage, run._stageUnit, step.units);

    run._stageUnit++;
    run._done++;
    run.progress = Math.min(99, Math.round((run._done / run._planTotal) * 100));

    if (run._stageUnit >= step.units) {
      stage.state = 'done';
      stage.meta = stageMeta(run, step.stage);
      run._stageIdx++;
      run._stageUnit = 0;
      emit(run, 'stage', run.stages);
    }
    emit(run, 'progress', run);
  }

  function stageMeta(run, stageId) {
    switch (stageId) {
      case 'discover': return run.counters.hosts + ' hosts';
      case 'identify': return run.counters.services + ' services';
      case 'analyze': return run.counters.findings + ' findings';
      case 'tls': return run._tlsHosts.length + ' endpoints';
      case 'headers': return run._httpHosts.length + ' responses';
      default: return null;
    }
  }

  function doUnit(run, stageId, unit, units) {
    const t = run._targets;
    if (stageId === 'discover') {
      const idx = Math.floor((unit / units) * t.length);
      const a = t[idx];
      if (a && run._discovered.indexOf(a) === -1) {
        run._discovered.push(a);
        run.counters.hosts = run._discovered.length;
        log(run, 'Host responding: ' + a.ip + (a.hostname ? '  ' + a.hostname : '') +
                 (a.vendor ? '  [' + a.vendor + ']' : ''), 'hit');
      }
    } else if (stageId === 'identify') {
      const all = run._allServices;
      const idx = Math.floor((unit / units) * all.length);
      const hit = all[idx];
      if (hit && run.counters.services < all.length) {
        run.counters.services = Math.min(all.length, run.counters.services + 1);
        if (unit % 3 === 0) {
          log(run, hit.a.ip + ':' + hit.s.port + '/' + hit.s.proto + '  ' + hit.s.name +
                   (hit.s.product ? '  ' + hit.s.product + (hit.s.version ? ' ' + hit.s.version : '') : ''), 'hit');
        }
      }
    } else if (stageId === 'tls') {
      const tlsHosts = run._tlsHosts;
      const idx = Math.floor((unit / units) * tlsHosts.length);
      const a = tlsHosts[idx];
      if (a && unit % 3 === 0) {
        log(run, 'TLS ' + a.ip + ':' + a.tls.port + '  ' + (a.tls.protocols || []).join(',') +
                 '  cert expires ' + CT.util.fmtDate(a.tls.cert.notAfter), 'info');
      }
    } else if (stageId === 'headers') {
      const httpHosts = run._httpHosts;
      const idx = Math.floor((unit / units) * httpHosts.length);
      const a = httpHosts[idx];
      if (a && unit % 3 === 0) {
        log(run, 'HTTP ' + a.ip + ':' + a.http.port + '  ' + a.http.status + '  ' +
                 Object.keys(a.http.headers || {}).length + ' headers', 'info');
      }
    } else if (stageId === 'analyze') {
      if (unit === 0) {
        const f = computeFindings(run);
        run._findings = f;
        run.counters.findings = f.length;
        f.slice(0, 6).forEach((x) =>
          log(run, '[' + CT.data.SEV_LABEL[x.severity].toUpperCase() + '] ' + x.title + ' — ' + x.assetLabel, 'fnd'));
        if (f.length > 6) log(run, '…and ' + (f.length - 6) + ' more findings', 'fnd');
      }
    }
  }

  /** Shape observations to the profile depth, then run the rule engine. */
  function computeFindings(run) {
    const depth = run.profile.depth;
    let observed = run._discovered.map((a) => {
      if (depth === 'services') return a;
      const copy = Object.assign({}, a);
      if (depth === 'hosts') { copy.services = []; copy.tls = null; copy.http = null; }
      if (depth === 'passive') {
        copy.services = (a.services || []).filter((s) => [1900, 5353, 137, 138].indexOf(s.port) !== -1);
        copy.tls = null; copy.http = null;
      }
      return copy;
    });

    let findings = CT.engines.analyzer.analyze(observed, {
      network: run.network, at: Date.now(), simulated: true,
      baseline: run._baseline, baselineAt: run._baselineAt
    });

    const allow = run.profile.rules;
    if (allow) findings = findings.filter((f) => allow.some((p) => f.ruleId.indexOf(p) === 0));
    run._observed = observed;
    return findings;
  }

  function finish(run) {
    clearInterval(run._timer);
    run.progress = 100;
    run.state = 'done';
    run.endedAt = Date.now();
    run.elapsedMs = run.endedAt - run.startedAt;

    const findings = run._findings || computeFindings(run);
    const observed = run._observed || run._discovered;
    const score = CT.engines.risk.scoreEnvironment(observed, findings);

    log(run, 'Assessment complete — ' + observed.length + ' assets, ' +
             run.counters.services + ' services, ' + findings.length + ' findings, score ' + score.score + '/100', 'info');

    const result = {
      id: run.id,
      startedAt: run.startedAt, endedAt: run.endedAt, durationMs: run.elapsedMs,
      scopeLabel: run.scopeLabel, scopeRaw: run.scope.raw,
      profileId: run.profile.id, profileName: run.profile.name,
      environmentId: run.environmentId, environmentName: run.environmentName,
      network: run.network,
      mode: run.mode, simulated: run.simulated,
      authorization: run.authorization,
      assets: observed, findings, score,
      stats: {
        hosts: observed.length,
        services: observed.reduce((a, x) => a + (x.services || []).length, 0),
        findings: findings.length
      },
      log: run.log.slice()
    };
    run.result = result;
    emit(run, 'progress', run);
    emit(run, 'state', run);
    emit(run, 'done', result);
    if (current === run) current = null;
  }

  return {
    PROFILES, profileById, STAGE_LABEL, ALL_STAGES, ERRORS,
    start, currentRun: () => current
  };
})();
