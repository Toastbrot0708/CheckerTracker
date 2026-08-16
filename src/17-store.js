/* ============================================================================
   MODULE: CT.store — application state, persistence, audit log
   ---------------------------------------------------------------------------
   Privacy posture: everything lives in this device's local storage. Nothing is
   transmitted anywhere. When a passcode is set the entire payload is sealed
   with AES-256-GCM before it is written, and the key exists only in memory for
   the duration of the unlocked session.

   Deliberately never stored: passwords, private keys, session tokens or any
   other credential material. The app has no mechanism to collect them.
   ========================================================================= */
CT.store = (function () {
  'use strict';

  const PLAIN_KEY = 'checkertracker.state.v1';
  const VAULT_KEY = 'checkertracker.vault.v1';
  const META_KEY = 'checkertracker.meta.v1';

  const DEFAULTS = () => ({
    version: 1,
    onboarded: false,
    environmentId: 'corp-lab',
    assessmentCounter: 40,
    assessments: [],
    currentAssessmentId: null,
    findingState: {},
    notifications: [],
    notes: [],
    savedScopes: [
      { id: 'sc-1', name: 'Office segment', value: '192.168.1.0/24' },
      { id: 'sc-2', name: 'Datacentre segment', value: '10.20.0.0/22' }
    ],
    audit: [],
    authorization: null,
    settings: {
      textScale: 'm',
      reduceMotion: false,
      privacyMode: true,
      passcodeEnabled: false,
      biometricPreferred: false,
      autoLockMinutes: 5,
      exportRequiresConfirm: true,
      showDemoWatermark: true,
      notifications: {
        newAsset: true, newFinding: true, criticalChange: true,
        certExpiry: true, newService: true, scoreChange: true
      }
    }
  });

  let state = DEFAULTS();
  let vaultKeyPhrase = null;       // held in memory only, cleared on lock
  let locked = false;
  const subscribers = new Set();

  /* -- Persistence --------------------------------------------------------- */
  function safeGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function safeSet(k, v) { try { localStorage.setItem(k, v); return true; } catch (e) { return false; } }
  function safeDel(k) { try { localStorage.removeItem(k); } catch (e) { /* ignore */ } }

  function meta() {
    try { return JSON.parse(safeGet(META_KEY) || '{}'); } catch (e) { return {}; }
  }
  function setMeta(m) { safeSet(META_KEY, JSON.stringify(m)); }

  let saveTimer = null;
  let persistFailed = false;
  function persist(immediate) {
    clearTimeout(saveTimer);
    const run = () => {
      // Locked with no key in memory: never fall through to a plaintext write,
      // which would silently strip the encryption the user asked for.
      if (state.settings.passcodeEnabled && !vaultKeyPhrase) return;
      if (state.settings.passcodeEnabled && vaultKeyPhrase) {
        CT.crypto.seal(vaultKeyPhrase, state)
          .then((env) => {
            persistFailed = !safeSet(VAULT_KEY, JSON.stringify(env));
            if (!persistFailed) safeDel(PLAIN_KEY);
          })
          .catch((e) => { persistFailed = true; console.error('[store] seal failed', e); });
      } else {
        persistFailed = !safeSet(PLAIN_KEY, JSON.stringify(state));
        if (!persistFailed) safeDel(VAULT_KEY);
      }
      if (persistFailed) {
        console.warn('[store] local storage write failed — the session continues in memory only');
      }
      setMeta({ encrypted: !!state.settings.passcodeEnabled, savedAt: Date.now(), version: 1 });
    };
    if (immediate) run(); else saveTimer = setTimeout(run, 250);
  }

  function hasVault() { return !!safeGet(VAULT_KEY); }

  function load() {
    if (hasVault()) { locked = true; return { locked: true }; }
    const raw = safeGet(PLAIN_KEY);
    if (raw) {
      try {
        const parsed = JSON.parse(raw);
        state = Object.assign(DEFAULTS(), parsed);
        state.settings = Object.assign(DEFAULTS().settings, parsed.settings || {});
        state.settings.notifications = Object.assign(DEFAULTS().settings.notifications, (parsed.settings || {}).notifications || {});
      } catch (e) {
        console.error('[store] state unreadable, starting fresh', e);
        state = DEFAULTS();
      }
    }
    locked = false;
    return { locked: false };
  }

  async function unlock(passphrase) {
    const raw = safeGet(VAULT_KEY);
    if (!raw) throw new Error('No encrypted vault is present on this device.');
    const env = JSON.parse(raw);
    const data = await CT.crypto.open(passphrase, env);   // throws on wrong passcode
    state = Object.assign(DEFAULTS(), data);
    state.settings = Object.assign(DEFAULTS().settings, data.settings || {});
    vaultKeyPhrase = passphrase;
    locked = false;
    audit('vault.unlock', 'Encrypted store unlocked');
    notify();
    return true;
  }

  function lock() {
    if (!state.settings.passcodeEnabled) return false;
    persist(true);
    vaultKeyPhrase = null;
    locked = true;
    notify();
    return true;
  }

  async function enablePasscode(passphrase) {
    if (!CT.crypto.available) throw new Error('WebCrypto is unavailable in this context, so the encrypted store cannot be enabled.');
    if (!passphrase || passphrase.length < 6) throw new Error('Passcode must be at least 6 characters.');
    vaultKeyPhrase = passphrase;
    state.settings.passcodeEnabled = true;
    audit('vault.enable', 'At-rest encryption enabled (AES-256-GCM, PBKDF2-SHA256, 210k iterations)');
    persist(true);
    notify();
  }

  async function disablePasscode() {
    state.settings.passcodeEnabled = false;
    vaultKeyPhrase = null;
    safeDel(VAULT_KEY);
    audit('vault.disable', 'At-rest encryption disabled');
    persist(true);
    notify();
  }

  /* -- Subscription -------------------------------------------------------- */
  function subscribe(fn) { subscribers.add(fn); return () => subscribers.delete(fn); }
  function notify() { subscribers.forEach((fn) => { try { fn(state); } catch (e) { console.error(e); } }); }
  function commit(immediate) { persist(immediate); notify(); }

  /* -- Audit log ----------------------------------------------------------- */
  function audit(action, detail, extra) {
    state.audit.unshift(Object.assign({
      id: CT.util.uid('log'), ts: Date.now(), actor: 'operator', action, detail
    }, extra || {}));
    if (state.audit.length > 500) state.audit.length = 500;
  }

  /* -- Notifications ------------------------------------------------------- */
  function pushNotification(n) {
    const cfg = state.settings.notifications;
    if (n.channel && cfg[n.channel] === false) return null;
    const item = Object.assign({
      id: CT.util.uid('ntf'), ts: Date.now(), read: false, kind: 'info'
    }, n);
    state.notifications.unshift(item);
    if (state.notifications.length > 200) state.notifications.length = 200;
    return item;
  }
  function markAllRead() {
    state.notifications.forEach((n) => { n.read = true; });
    commit();
  }
  function unreadCount() { return state.notifications.filter((n) => !n.read).length; }

  /* -- Assessments --------------------------------------------------------- */
  function nextNumber() { return ++state.assessmentCounter; }

  function saveAssessment(result, opts) {
    const o = opts || {};
    const previous = currentAssessment();
    const record = Object.assign({}, result, {
      number: o.number || nextNumber(),
      savedAt: Date.now()
    });
    state.assessments.push(record);
    if (state.assessments.length > 40) state.assessments.shift();
    state.currentAssessmentId = record.id;

    audit('scan.complete', 'Assessment #' + String(record.number).padStart(3, '0') + ' — ' +
      record.scopeLabel + ' · ' + record.profileName + ' · ' + record.stats.hosts + ' assets, ' +
      record.stats.findings + ' findings', { mode: record.mode });

    if (previous && !o.silent) generateNotifications(previous, record);
    commit(true);
    return record;
  }

  function generateNotifications(prev, curr) {
    const d = CT.engines.assetdb.diffSnapshots(prev.assets, curr.assets);
    const fd = CT.engines.assetdb.diffFindings(prev.findings, curr.findings);

    d.added.forEach((a) => pushNotification({
      channel: a.inInventory === false ? 'newAsset' : 'newAsset',
      kind: a.inInventory === false ? 'warn' : 'info',
      title: a.inInventory === false ? 'Unknown asset detected' : 'New asset detected',
      body: a.inInventory === false
        ? 'A previously unknown device was detected on the monitored network.'
        : 'A new device joined the monitored network.',
      meta: (a.hostname || 'unnamed') + ' · ' + a.ip,
      route: '#/asset/' + a.id
    }));

    d.newServices.filter((s) => !s.viaNewAsset).forEach((s) => pushNotification({
      channel: 'newService', kind: 'info',
      title: 'New service detected',
      body: 'Port ' + s.service.port + '/' + s.service.proto + ' (' + s.service.name + ') is now responding.',
      meta: (s.asset.hostname || s.asset.ip),
      route: '#/asset/' + s.asset.id
    }));

    fd.added.forEach((f) => {
      if (f.severity === 'critical' || f.severity === 'high') {
        pushNotification({
          channel: 'newFinding', kind: f.severity === 'critical' ? 'crit' : 'warn',
          title: CT.data.SEV_LABEL[f.severity] + ' finding: ' + f.title,
          body: f.detail || CT.data.rule(f.ruleId).description,
          meta: f.assetLabel, route: '#/finding/' + encodeURIComponent(f.id)
        });
      }
    });

    curr.assets.forEach((a) => {
      if (a.tls && a.tls.cert) {
        const days = Math.floor((a.tls.cert.notAfter - Date.now()) / 86400000);
        if (days >= 0 && days <= 30) {
          pushNotification({
            channel: 'certExpiry', kind: days <= 7 ? 'crit' : 'warn',
            title: 'Certificate expiring in ' + days + ' day(s)',
            body: 'The certificate on ' + (a.hostname || a.ip) + ' expires ' + CT.util.fmtDate(a.tls.cert.notAfter) + '.',
            meta: a.tls.cert.subjectCN || a.ip, route: '#/asset/' + a.id
          });
        }
      }
    });

    const delta = curr.score.score - prev.score.score;
    if (delta !== 0) {
      pushNotification({
        channel: 'scoreChange', kind: delta > 0 ? 'ok' : 'warn',
        title: 'Security score ' + (delta > 0 ? 'improved' : 'declined') + ' by ' + Math.abs(delta) + ' points',
        body: 'Now ' + curr.score.score + '/100, previously ' + prev.score.score + '/100.',
        meta: curr.scopeLabel, route: '#/compare'
      });
    }
  }

  /* -- Finding state ------------------------------------------------------- */
  function applyFindingState(findings) {
    return findings.map((f) => {
      const s = state.findingState[f.id];
      return s ? Object.assign({}, f, s) : f;
    });
  }

  function setFindingStatus(findingId, status, extra) {
    const prev = state.findingState[findingId] || {};
    state.findingState[findingId] = Object.assign({}, prev, { status, updatedAt: Date.now() }, extra || {});
    audit('finding.status', 'Finding ' + findingId + ' set to "' + status + '"');
    commit();
  }
  function addFindingNote(findingId, text) {
    const prev = state.findingState[findingId] || {};
    const notes = (prev.notes || []).concat([{ ts: Date.now(), text, author: 'operator' }]);
    state.findingState[findingId] = Object.assign({}, prev, { notes, updatedAt: Date.now() });
    audit('finding.note', 'Note added to finding ' + findingId);
    commit();
  }
  function assignFinding(findingId, assignee) {
    const prev = state.findingState[findingId] || {};
    state.findingState[findingId] = Object.assign({}, prev, { assignee: assignee || null, updatedAt: Date.now() });
    audit('finding.assign', 'Finding ' + findingId + ' assigned to ' + (assignee || 'nobody'));
    commit();
  }

  /* -- Selectors ----------------------------------------------------------- */
  function currentAssessment() {
    if (!state.assessments.length) return null;
    if (state.currentAssessmentId) {
      const f = state.assessments.find((a) => a.id === state.currentAssessmentId);
      if (f) return f;
    }
    return state.assessments[state.assessments.length - 1];
  }
  function previousAssessment() {
    const cur = currentAssessment();
    if (!cur) return null;
    const idx = state.assessments.indexOf(cur);
    return idx > 0 ? state.assessments[idx - 1] : null;
  }
  function assets() { const a = currentAssessment(); return a ? a.assets : []; }
  function findings() { const a = currentAssessment(); return a ? applyFindingState(a.findings) : []; }
  function activeFindings() { return findings().filter((f) => f.status !== 'resolved' && f.status !== 'accepted'); }
  function liveScore() {
    const a = currentAssessment();
    if (!a) return null;
    return CT.engines.risk.scoreEnvironment(a.assets, findings());
  }
  function assetById(id) { return assets().find((a) => a.id === id) || null; }
  function findingById(id) { return findings().find((f) => f.id === id) || null; }
  function network() { const a = currentAssessment(); return a ? a.network : null; }

  /* -- Settings ------------------------------------------------------------ */
  function setSetting(path, value) {
    const parts = path.split('.');
    let obj = state.settings;
    for (let i = 0; i < parts.length - 1; i++) obj = obj[parts[i]];
    obj[parts[parts.length - 1]] = value;
    audit('settings.change', path + ' = ' + JSON.stringify(value));
    commit();
  }

  function setEnvironment(id) {
    state.environmentId = id;
    audit('environment.select', 'Environment set to ' + id);
    commit();
  }

  function addNote(text, assessmentId) {
    state.notes.unshift({ id: CT.util.uid('note'), ts: Date.now(), text, assessmentId: assessmentId || (currentAssessment() || {}).id || null });
    audit('note.add', 'Assessment note added');
    commit();
  }
  function deleteNote(id) {
    state.notes = state.notes.filter((n) => n.id !== id);
    audit('note.delete', 'Assessment note deleted');
    commit();
  }

  function saveScope(name, value) {
    state.savedScopes.push({ id: CT.util.uid('sc'), name, value });
    audit('scope.save', 'Saved scope "' + name + '" = ' + value);
    commit();
  }
  function deleteScope(id) {
    state.savedScopes = state.savedScopes.filter((s) => s.id !== id);
    commit();
  }

  function grantAuthorization(scopeLabel, hours) {
    state.authorization = {
      scope: scopeLabel, grantedAt: Date.now(),
      expiresAt: Date.now() + (hours || 24) * 3600000,
      confirmedBy: 'operator'
    };
    audit('authorization.grant', 'Authorization confirmed for ' + scopeLabel +
      ' — valid ' + (hours || 24) + 'h', { scope: scopeLabel });
    commit();
    return state.authorization;
  }
  function authorizationValid(scopeLabel) {
    const a = state.authorization;
    if (!a) return false;
    if (Date.now() > a.expiresAt) return false;
    return !scopeLabel || a.scope === scopeLabel;
  }
  function revokeAuthorization() {
    state.authorization = null;
    audit('authorization.revoke', 'Authorization window cleared');
    commit();
  }

  function reset() {
    audit('app.reset', 'All local data cleared');
    safeDel(PLAIN_KEY); safeDel(VAULT_KEY); safeDel(META_KEY);
    state = DEFAULTS();
    vaultKeyPhrase = null;
    locked = false;
    commit(true);
  }

  /* -- Demo seeding --------------------------------------------------------
     Builds a previous and a current assessment from a demo environment so
     history, notifications and comparison are populated with data that was
     genuinely produced by the analysis engines.                            */
  function seedDemo(environmentId) {
    const envId = environmentId || 'corp-lab';
    const env = CT.demo.build(envId);
    const prevSnap = CT.demo.previousSnapshot(env);

    const prevFindings = CT.engines.analyzer.analyze(prevSnap.assets, {
      network: prevSnap.network, at: prevSnap.at, simulated: true
    });
    const prevScore = CT.engines.risk.scoreEnvironment(prevSnap.assets, prevFindings);
    const prevRecord = {
      id: 'demo-prev-' + envId, number: 41,
      startedAt: prevSnap.at - 272000, endedAt: prevSnap.at, durationMs: 272000,
      scopeLabel: env.network.subnet, scopeRaw: env.network.subnet,
      profileId: 'full', profileName: 'Full Assessment',
      environmentId: envId, environmentName: env.network.name,
      network: prevSnap.network, mode: 'simulated', simulated: true,
      authorization: { scope: env.network.subnet, grantedAt: prevSnap.at - 300000, expiresAt: prevSnap.at + 86400000, confirmedBy: 'operator' },
      assets: prevSnap.assets, findings: prevFindings, score: prevScore,
      stats: { hosts: prevSnap.assets.length,
               services: prevSnap.assets.reduce((a, x) => a + (x.services || []).length, 0),
               findings: prevFindings.length },
      log: [], savedAt: prevSnap.at
    };

    const now = Date.now();
    const currFindings = CT.engines.analyzer.analyze(env.assets, {
      network: env.network, at: now, simulated: true,
      baseline: prevSnap.assets, baselineAt: prevSnap.at
    });
    const currScore = CT.engines.risk.scoreEnvironment(env.assets, currFindings);
    const currRecord = {
      id: 'demo-curr-' + envId, number: 42,
      startedAt: now - 261000, endedAt: now - 1000, durationMs: 260000,
      scopeLabel: env.network.subnet, scopeRaw: env.network.subnet,
      profileId: 'full', profileName: 'Full Assessment',
      environmentId: envId, environmentName: env.network.name,
      network: env.network, mode: 'simulated', simulated: true,
      authorization: { scope: env.network.subnet, grantedAt: now - 300000, expiresAt: now + 86400000, confirmedBy: 'operator' },
      assets: env.assets, findings: currFindings, score: currScore,
      stats: { hosts: env.assets.length,
               services: env.assets.reduce((a, x) => a + (x.services || []).length, 0),
               findings: currFindings.length },
      log: [], savedAt: now - 1000
    };

    state.environmentId = envId;
    state.assessments = [prevRecord, currRecord];
    state.assessmentCounter = 42;
    state.currentAssessmentId = currRecord.id;
    state.findingState = {};
    state.notifications = [];
    state.onboarded = true;
    state.authorization = currRecord.authorization;

    audit('demo.load', 'Demo environment "' + env.network.name + '" loaded — ' +
      env.assets.length + ' simulated assets, 2 assessments', { mode: 'simulated' });
    generateNotifications(prevRecord, currRecord);
    commit(true);
    return currRecord;
  }

  function startFresh() {
    state.onboarded = true;
    state.assessments = [];
    state.currentAssessmentId = null;
    state.notifications = [];
    audit('app.start', 'Started with an empty environment');
    commit(true);
  }

  /** Import an assessment previously exported as CheckerTracker JSON. */
  function importAssessment(json) {
    let data;
    try { data = typeof json === 'string' ? JSON.parse(json) : json; }
    catch (e) { throw new Error('That is not valid JSON.'); }
    if (!data || data.schema !== 'checkertracker.report/1') {
      throw new Error('Unrecognised file. Expected a CheckerTracker JSON export (schema checkertracker.report/1).');
    }
    const assets = (data.assets || []).map((a) => ({
      id: a.id || CT.util.uid('imp'), hostname: a.hostname, ip: a.ip, ipv6: a.ipv6, mac: a.mac,
      vendor: a.vendor, deviceType: a.deviceType || 'Unknown', os: a.os, osConfidence: 'medium',
      owner: a.owner, inInventory: a.inInventory !== false, status: a.status || 'reachable',
      firstSeen: Date.parse(a.firstSeen) || Date.now(), lastSeen: Date.parse(a.lastSeen) || Date.now(),
      services: (a.services || []).map((s) => ({
        port: s.port, proto: s.protocol || 'tcp', name: s.service || (CT.data.portInfo(s.port) || {}).name || 'unknown',
        service: (CT.data.portInfo(s.port) || {}).service || '', product: s.product, version: s.version
      })),
      tls: a.tls ? {
        port: a.tls.port, protocols: a.tls.protocols, cipher: a.tls.cipher,
        cert: a.tls.certificate ? {
          subjectCN: a.tls.certificate.subjectCN, issuerCN: a.tls.certificate.issuerCN,
          notBefore: Date.parse(a.tls.certificate.notBefore), notAfter: Date.parse(a.tls.certificate.notAfter),
          sigAlg: a.tls.certificate.signatureAlgorithm, keyAlg: a.tls.certificate.keyAlgorithm,
          keyBits: a.tls.certificate.keyBits, selfSigned: a.tls.certificate.selfSigned,
          san: a.tls.certificate.san || []
        } : null
      } : null,
      http: null, tags: []
    }));
    if (!assets.length) throw new Error('The file contains no assets.');

    const findings = CT.engines.analyzer.analyze(assets, {
      network: null, at: Date.now(), simulated: !!(data.dataOrigin || '').match(/SIMULATED/)
    });
    const score = CT.engines.risk.scoreEnvironment(assets, findings);
    const record = {
      id: CT.util.uid('imp'), number: nextNumber(),
      startedAt: Date.parse((data.assessment || {}).startedAt) || Date.now(),
      endedAt: Date.parse((data.assessment || {}).endedAt) || Date.now(),
      durationMs: (data.assessment || {}).durationMs || 0,
      scopeLabel: (data.assessment || {}).scope || 'imported',
      scopeRaw: (data.assessment || {}).scope || '',
      profileId: (data.assessment || {}).profileId || 'full',
      profileName: ((data.assessment || {}).profile || 'Imported dataset'),
      environmentId: 'imported', environmentName: (data.assessment || {}).environment || 'Imported',
      network: null,
      mode: 'imported', simulated: /SIMULATED/i.test(data.dataOrigin || ''),
      imported: true, importedFrom: data.tool || 'unknown', importedAt: Date.now(),
      authorization: null,
      assets, findings, score,
      stats: { hosts: assets.length, services: assets.reduce((a, x) => a + x.services.length, 0), findings: findings.length },
      log: []
    };
    state.assessments.push(record);
    state.currentAssessmentId = record.id;
    state.onboarded = true;
    audit('assessment.import', 'Imported assessment with ' + assets.length + ' assets from ' + (data.tool || 'unknown source'));
    commit(true);
    return record;
  }

  return {
    get state() { return state; },
    get locked() { return locked; },
    persistFailed: () => persistFailed,
    hasVault, load, unlock, lock, enablePasscode, disablePasscode,
    subscribe, notify, commit, audit, persist,
    pushNotification, markAllRead, unreadCount,
    saveAssessment, currentAssessment, previousAssessment,
    assets, findings, activeFindings, liveScore, assetById, findingById, network,
    applyFindingState, setFindingStatus, addFindingNote, assignFinding,
    setSetting, setEnvironment, addNote, deleteNote, saveScope, deleteScope,
    grantAuthorization, authorizationValid, revokeAuthorization,
    reset, seedDemo, startFresh, importAssessment,
    setCurrentAssessment(id) { state.currentAssessmentId = id; commit(); }
  };
})();
