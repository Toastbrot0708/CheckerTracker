/* ============================================================================
   One assessment run: sequencing, progress, pause, cancel.
   ========================================================================= */
'use strict';

const { Control } = require('./pool');
const probe = require('./probe');
const arp = require('./arp');
const stages = require('./stages');
const build = require('./asset-build');

class Assessment {
  constructor(config) {
    this.id = config.id;
    this.scope = config.scope;
    this.depth = config.depth || 'services';
    this.stageIds = config.stages || [];
    this.gateway = config.gateway || null;
    this.ports = config.ports || probe.TOP_PORTS;
    this.concurrency = config.concurrency || 96;

    this.control = new Control();
    this.state = 'running';
    this.startedAt = Date.now();
    this.endedAt = null;
    this.progress = 0;
    this.assets = [];
    this.log = [];
    this.counters = { hosts: 0, hostsTotal: this.scope.total, services: 0 };
    this._listeners = {};
    this._units = this.scope.total;    // grows once the live set is known
    this._done = 0;
  }

  on(type, fn) { (this._listeners[type] = this._listeners[type] || []).push(fn); return this; }

  emit(type, payload) {
    (this._listeners[type] || []).forEach((fn) => {
      try { fn(payload); } catch (e) { /* a listener must not break a run */ }
    });
  }

  addLog(text, kind) {
    const entry = { ts: Date.now(), text, kind: kind || 'info' };
    this.log.push(entry);
    if (this.log.length > 800) this.log.shift();
    this.emit('log', entry);
  }

  tick() {
    this._done++;
    const pct = Math.min(99, Math.round((this._done / Math.max(1, this._units)) * 100));
    if (pct !== this.progress) {
      this.progress = pct;
      this.emit('progress', { progress: pct, counters: this.counters });
    }
  }

  setStage(id, state, meta) {
    this.emit('stage', { id, state, meta: meta || null });
  }

  pause() { this.control.pause(); this.state = 'paused'; this.emit('state', this.state); }
  resume() { this.control.resume(); this.state = 'running'; this.emit('state', this.state); }
  cancel() { this.control.cancel(); this.state = 'cancelled'; this.emit('state', this.state); }

  wants(stage) { return this.stageIds.indexOf(stage) !== -1; }

  async run() {
    const ctx = {
      scope: this.scope,
      depth: this.depth,
      ports: this.ports,
      gateway: this.gateway,
      concurrency: this.concurrency,
      control: this.control,
      log: (text, kind) => this.addLog(text, kind),
      emit: (type, payload) => this.emit(type, payload),
      tick: () => this.tick()
    };

    try {
      this.setStage('authorize', 'active');
      this.addLog('Scope authorized: ' + this.scope.label + ' (' +
        this.scope.total + ' addresses)');
      this.setStage('authorize', 'done', this.scope.total + ' addresses');

      /* -- discover ------------------------------------------------------ */
      this.setStage('discover', 'active');
      const live = await stages.discover(ctx);
      this.counters.hosts = live.length;
      this.setStage('discover', 'done', live.length + ' hosts');

      if (!live.length) { this.finish([]); return; }

      // Re-plan now that the real host count is known.
      this._units += live.length * 2;

      /* -- identify ------------------------------------------------------ */
      let portMap = new Map();
      if (this.wants('identify')) {
        this.setStage('identify', 'active');
        portMap = await stages.identifyServices(ctx, live);
        this.counters.services = Array.from(portMap.values())
          .reduce((sum, s) => sum + s.open.length, 0);
        this.setStage('identify', 'done', this.counters.services + ' services');
      }

      /* -- metadata ------------------------------------------------------ */
      // The ARP cache is only populated now, after the sweep has actually
      // exchanged frames with these hosts.
      const macTable = await arp.table((ip) => this.scope.contains(ip));
      this.setStage('metadata', 'active');
      const meta = await stages.metadata(ctx, live, portMap, macTable);
      this.setStage('metadata', 'done', macTable.size + ' MAC addresses');

      /* -- tls ----------------------------------------------------------- */
      let tlsMap = new Map();
      if (this.wants('tls')) {
        const targets = stages.pickTargets(live, portMap, meta, (p) => probe.TLS_PORTS.has(p));
        this._units += targets.length;
        this.setStage('tls', 'active');
        tlsMap = await stages.inspectTls(ctx, targets);
        this.setStage('tls', 'done', tlsMap.size + ' endpoints');
      }

      /* -- headers -------------------------------------------------------- */
      let httpMap = new Map();
      if (this.wants('headers')) {
        const targets = stages.pickTargets(live, portMap, meta,
          (p) => probe.HTTP_PORTS.has(p) || probe.TLS_PORTS.has(p));
        this._units += targets.length;
        this.setStage('headers', 'active');
        httpMap = await stages.inspectHttp(ctx, targets);
        this.setStage('headers', 'done', httpMap.size + ' responses');
      }

      /* -- assemble -------------------------------------------------------- */
      const observedAt = Date.now();
      const assets = live.map((host) => {
        const info = meta.get(host.ip) || {};
        const tls = tlsMap.get(host.ip);
        return build.buildAsset({
          ip: host.ip,
          liveness: host,
          portScan: portMap.get(host.ip) || null,
          banners: info.banners,
          name: info.name,
          macEntry: info.macEntry,
          ttl: info.ttl,
          classification: info.classification,
          tls: tls ? build.tlsRecord(tls) : null,
          http: httpMap.get(host.ip) || null,
          observedAt
        });
      });

      this.finish(assets);
    } catch (err) {
      if (err && err.code === 'CANCELLED') {
        this.state = 'cancelled';
        this.endedAt = Date.now();
        this.emit('error', { code: 'cancelled', message: err.message });
        return;
      }
      this.state = 'error';
      this.endedAt = Date.now();
      this.addLog('Assessment failed: ' + (err && err.message), 'fnd');
      this.emit('error', { code: 'error', message: err ? String(err.message) : 'unknown' });
    }
  }

  finish(assets) {
    this.assets = assets;
    this.progress = 100;
    this.state = 'done';
    this.endedAt = Date.now();
    this.counters.services = assets.reduce((n, a) => n + a.services.length, 0);
    this.addLog('Sweep complete: ' + assets.length + ' hosts, ' +
      this.counters.services + ' services observed');
    this.emit('progress', { progress: 100, counters: this.counters });
    this.emit('done', {
      id: this.id,
      startedAt: this.startedAt,
      endedAt: this.endedAt,
      durationMs: this.endedAt - this.startedAt,
      scopeLabel: this.scope.label,
      assets,
      counters: this.counters,
      log: this.log.slice()
    });
  }
}

module.exports = { Assessment };
