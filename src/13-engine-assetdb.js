/* ============================================================================
   MODULE: CT.engines.assetdb — snapshot history and comparison
   ========================================================================= */
CT.engines.assetdb = (function () {
  'use strict';

  function keyOf(a) { return a.id; }
  function svcKey(s) { return s.port + '/' + s.proto; }

  /** Compare two asset snapshots. Everything here is computed, not stored. */
  function diffSnapshots(prevAssets, currAssets) {
    const prevMap = new Map(prevAssets.map((a) => [keyOf(a), a]));
    const currMap = new Map(currAssets.map((a) => [keyOf(a), a]));

    const added = currAssets.filter((a) => !prevMap.has(keyOf(a)));
    const removed = prevAssets.filter((a) => !currMap.has(keyOf(a)));
    const persisted = currAssets.filter((a) => prevMap.has(keyOf(a)));

    const newServices = [], removedServices = [];
    persisted.forEach((a) => {
      const p = prevMap.get(keyOf(a));
      const prevSet = new Set((p.services || []).map(svcKey));
      const currSet = new Set((a.services || []).map(svcKey));
      (a.services || []).forEach((s) => { if (!prevSet.has(svcKey(s))) newServices.push({ asset: a, service: s }); });
      (p.services || []).forEach((s) => { if (!currSet.has(svcKey(s))) removedServices.push({ asset: a, service: s }); });
    });
    // Services on brand-new assets count as newly observed too.
    added.forEach((a) => (a.services || []).forEach((s) => newServices.push({ asset: a, service: s, viaNewAsset: true })));

    return { added, removed, persisted, newServices, removedServices };
  }

  function diffFindings(prevFindings, currFindings) {
    const prevMap = new Map(prevFindings.map((f) => [f.id, f]));
    const currMap = new Map(currFindings.map((f) => [f.id, f]));
    return {
      added: currFindings.filter((f) => !prevMap.has(f.id)),
      resolved: prevFindings.filter((f) => !currMap.has(f.id)),
      persisting: currFindings.filter((f) => prevMap.has(f.id))
    };
  }

  /** Build a human-readable change history for one asset across two snapshots. */
  function assetHistory(curr, prev, prevAt, currAt) {
    const events = [];
    if (!prev) {
      events.push({ ts: curr.firstSeen, kind: 'info', text: 'Asset first observed at ' + curr.ip });
      (curr.services || []).forEach((s) =>
        events.push({ ts: curr.firstSeen, kind: 'info', text: 'Port ' + s.port + '/' + s.proto + ' first seen' }));
      return events.sort((a, b) => b.ts - a.ts);
    }
    const prevSet = new Set((prev.services || []).map(svcKey));
    const currSet = new Set((curr.services || []).map(svcKey));
    (curr.services || []).forEach((s) => {
      if (!prevSet.has(svcKey(s))) events.push({ ts: currAt, kind: 'warn', text: 'Port ' + s.port + '/' + s.proto + ' appeared' });
    });
    (prev.services || []).forEach((s) => {
      if (!currSet.has(svcKey(s))) events.push({ ts: currAt, kind: 'ok', text: 'Port ' + s.port + '/' + s.proto + ' no longer responding' });
    });
    if (prev.ip !== curr.ip) events.push({ ts: currAt, kind: 'warn', text: 'Address changed from ' + prev.ip + ' to ' + curr.ip });
    if (prev.hostname !== curr.hostname) {
      events.push({ ts: currAt, kind: 'info', text: 'Hostname changed from ' + (prev.hostname || 'unresolved') + ' to ' + (curr.hostname || 'unresolved') });
    }
    if (prev.os !== curr.os) events.push({ ts: currAt, kind: 'info', text: 'Operating system indicator changed to ' + (curr.os || 'unknown') });
    const pc = prev.tls && prev.tls.cert, cc = curr.tls && curr.tls.cert;
    if (pc && cc) {
      if (pc.notAfter !== cc.notAfter || pc.sigAlg !== cc.sigAlg || pc.keyBits !== cc.keyBits) {
        events.push({ ts: currAt, kind: 'warn', text: 'Certificate changed (expiry ' + CT.util.fmtDate(cc.notAfter) + ', ' + cc.sigAlg + ', ' + cc.keyBits + '-bit)' });
      }
    } else if (!pc && cc) {
      events.push({ ts: currAt, kind: 'info', text: 'TLS certificate first observed' });
    } else if (pc && !cc) {
      events.push({ ts: currAt, kind: 'warn', text: 'TLS service no longer observed' });
    }
    events.push({ ts: prevAt, kind: 'info', text: 'Observed in previous assessment' });
    events.push({ ts: curr.firstSeen, kind: 'info', text: 'Asset first observed at ' + curr.ip });
    return events.sort((a, b) => b.ts - a.ts);
  }

  return { diffSnapshots, diffFindings, assetHistory, svcKey };
})();
