/* ============================================================================
   MODULE: CT.engines.risk — explainable scoring
   The environment score is a weighted sum of five measured dimensions. Every
   point deducted is attributable to a specific dimension and to the findings
   inside it, so the number can always be defended.
   ========================================================================= */
CT.engines.risk = (function () {
  'use strict';

  const DIMENSIONS = [
    { key: 'visibility', label: 'Asset visibility', weight: 0.15,
      about: 'How completely each responding device is identified — hostname, vendor, operating system and recorded owner.' },
    { key: 'exposure', label: 'Network exposure', weight: 0.30,
      about: 'Administrative, remote-access, database and cleartext services reachable inside the scope.' },
    { key: 'tls', label: 'TLS posture', weight: 0.20,
      about: 'Certificate validity and protocol configuration across every service that offered TLS.' },
    { key: 'configuration', label: 'Configuration', weight: 0.25,
      about: 'Security headers, cookie attributes, default configurations, version currency and segmentation.' },
    { key: 'unknown', label: 'Unknown assets', weight: 0.10,
      about: 'Proportion of responding devices that are present in the expected inventory.' }
  ];

  const RULE_DIMENSION = {
    'CT-NET-001': 'exposure', 'CT-NET-002': 'exposure', 'CT-NET-003': 'exposure',
    'CT-NET-004': 'exposure', 'CT-NET-005': 'exposure', 'CT-NET-006': 'exposure',
    'CT-NET-007': 'exposure', 'CT-NET-008': 'exposure', 'CT-NET-009': 'exposure',
    'CT-CFG-003': 'exposure',
    'CT-TLS-001': 'tls', 'CT-TLS-002': 'tls', 'CT-TLS-003': 'tls', 'CT-TLS-004': 'tls',
    'CT-TLS-005': 'tls', 'CT-TLS-006': 'tls', 'CT-TLS-007': 'tls',
    'CT-WEB-001': 'configuration', 'CT-WEB-002': 'configuration', 'CT-WEB-003': 'configuration',
    'CT-WEB-004': 'configuration', 'CT-WEB-005': 'configuration', 'CT-WEB-006': 'configuration',
    'CT-WEB-007': 'configuration', 'CT-WEB-008': 'configuration',
    'CT-CFG-001': 'configuration', 'CT-CFG-002': 'configuration', 'CT-CFG-004': 'configuration',
    'CT-INV-001': 'unknown', 'CT-INV-002': 'unknown'
  };

  const GRADES = [
    { min: 90, label: 'Strong', kind: 'ok' },
    { min: 75, label: 'Good', kind: 'ok' },
    { min: 60, label: 'Fair', kind: 'warn' },
    { min: 40, label: 'Weak', kind: 'bad' },
    { min: 0, label: 'Critical', kind: 'crit' }
  ];
  function grade(score) { return GRADES.find((g) => score >= g.min); }

  function penaltyOf(findings) {
    return findings.reduce((a, f) => a + (f.status === 'resolved' || f.status === 'accepted'
      ? 0 : (CT.data.SEV_WEIGHT[f.severity] || 0)), 0);
  }

  /** Environment score with a full, reproducible derivation. */
  function scoreEnvironment(assets, findings) {
    const n = assets.length;
    const active = findings.filter((f) => f.status !== 'resolved' && f.status !== 'accepted');

    if (!n) {
      return { score: 0, grade: grade(0), breakdown: DIMENSIONS.map((d) =>
        Object.assign({}, d, { pct: 0, pointsLost: 0, detail: 'No assets in scope.', findingIds: [] })),
        attention: 0, totalFindings: 0, method: 'No assets were observed, so no score can be derived.' };
    }

    // Dimension 1 — asset visibility (identity completeness)
    let known = 0, slots = 0;
    assets.forEach((a) => {
      slots += 4;
      if (a.hostname) known++;
      if (a.vendor) known++;
      if (a.os) known++;
      if (a.owner) known++;
    });
    const visibilityPct = Math.round((known / slots) * 100);

    // Dimension 5 — inventory coverage
    const inInv = assets.filter((a) => a.inInventory !== false).length;
    const unknownPct = Math.round((inInv / n) * 100);

    // Dimensions 2–4 — severity-weighted penalties normalised against a
    // capacity that scales with how much there is to get wrong.
    // Penalty capacity scales with how much there is to get wrong, so the
    // score discriminates instead of pinning to 0 on a busy estate. The
    // multipliers are calibrated so a well-run environment lands in the 80s
    // and one with an expired certificate, exposed remote desktop and an
    // unmanaged device lands in the 60s.
    const tlsAssets = assets.filter((a) => !!a.tls).length;
    const bases = {
      exposure: Math.max(60, n * 32),
      tls: Math.max(60, tlsAssets * 75),
      configuration: Math.max(60, n * 28)
    };

    const buckets = { exposure: [], tls: [], configuration: [], unknown: [], visibility: [] };
    active.forEach((f) => {
      const d = RULE_DIMENSION[f.ruleId] || 'configuration';
      buckets[d].push(f);
    });

    const pcts = { visibility: visibilityPct, unknown: unknownPct };
    ['exposure', 'tls', 'configuration'].forEach((k) => {
      if (k === 'tls' && tlsAssets === 0) { pcts.tls = 100; return; }
      const pen = penaltyOf(buckets[k]);
      pcts[k] = Math.round(CT.util.clamp(100 - (100 * pen / bases[k]), 0, 100));
    });

    const breakdown = DIMENSIONS.map((d) => {
      const pct = pcts[d.key];
      const pointsLost = Math.round((100 - pct) * d.weight * 10) / 10;
      let detail;
      if (d.key === 'visibility') {
        detail = known + ' of ' + slots + ' identity attributes resolved across ' + CT.util.plural(n, 'asset') + '.';
      } else if (d.key === 'unknown') {
        detail = inInv + ' of ' + n + ' responding devices are in the expected inventory.';
      } else if (d.key === 'tls' && tlsAssets === 0) {
        detail = 'No TLS services were observed in scope.';
      } else {
        detail = 'Severity-weighted penalty ' + Math.round(penaltyOf(buckets[d.key]) * 10) / 10 +
                 ' against a capacity of ' + bases[d.key] + ' (' + CT.util.plural(buckets[d.key].length, 'finding') + ').';
      }
      return Object.assign({}, d, { pct, pointsLost, detail, findingIds: buckets[d.key].map((f) => f.id) });
    });

    const score = Math.round(breakdown.reduce((a, d) => a + d.pct * d.weight, 0));
    const attention = active.filter((f) => f.severity === 'critical' || f.severity === 'high').length;

    return {
      score: CT.util.clamp(score, 0, 100),
      grade: grade(score),
      breakdown,
      attention,
      totalFindings: active.length,
      counts: countBySeverity(active),
      method: 'Weighted sum of five measured dimensions. Each dimension is scored 0–100, multiplied by its weight, ' +
              'and the products are summed. Severity weights: critical 40, high 18, medium 7, low 2.5, informational 0.'
    };
  }

  function countBySeverity(findings) {
    const c = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
    findings.forEach((f) => { if (c[f.severity] !== undefined) c[f.severity]++; });
    return c;
  }

  function fromList(mine) {
    const raw = mine.reduce((a, f) => a + (CT.data.SEV_WEIGHT[f.severity] || 0), 0);
    const score = Math.round(CT.util.clamp(raw, 0, 100));
    const level = score >= 55 ? 'critical' : score >= 28 ? 'high' : score >= 10 ? 'medium' : score > 0 ? 'low' : 'ok';
    return {
      score, level,
      label: level === 'ok' ? 'No findings' : CT.data.SEV_LABEL[level] + ' risk',
      counts: countBySeverity(mine),
      findings: mine
    };
  }

  /** Per-asset risk indicator (higher = more exposure). */
  function scoreAsset(asset, findings) {
    return fromList(findings.filter((f) =>
      f.assetId === asset.id && f.status !== 'resolved' && f.status !== 'accepted'));
  }

  /**
   * Score a whole inventory in one pass. Indexing findings by asset once keeps
   * a 500-asset list linear instead of quadratic.
   */
  function scoreAll(assets, findings) {
    const byAsset = new Map();
    findings.forEach((f) => {
      if (f.status === 'resolved' || f.status === 'accepted' || !f.assetId) return;
      const list = byAsset.get(f.assetId);
      if (list) list.push(f); else byAsset.set(f.assetId, [f]);
    });
    return assets.map((a) => ({ asset: a, risk: fromList(byAsset.get(a.id) || []) }));
  }

  return { DIMENSIONS, RULE_DIMENSION, scoreEnvironment, scoreAsset, scoreAll, countBySeverity, grade, GRADES };
})();
