/* ============================================================================
   MODULE: CT.engines.report — report model + JSON / CSV / print export
   ========================================================================= */
CT.engines.report = (function () {
  'use strict';

  const TYPES = [
    { id: 'executive', name: 'Executive Summary', icon: 'trendUp',
      desc: 'Posture, score movement and the decisions that need to be made.',
      sections: ['header', 'summary', 'score', 'topFindings', 'recommendations', 'timeline', 'disclaimer'] },
    { id: 'technical', name: 'Technical Assessment', icon: 'terminal',
      desc: 'Full detail: scope, methodology, assets, every finding with evidence.',
      sections: ['header', 'summary', 'scope', 'methodology', 'score', 'assets', 'findings', 'recommendations', 'timeline', 'disclaimer'] },
    { id: 'inventory', name: 'Asset Inventory', icon: 'database',
      desc: 'Every responding device with identity, services and last sighting.',
      sections: ['header', 'scope', 'assets', 'timeline', 'disclaimer'] },
    { id: 'findings', name: 'Findings Report', icon: 'alert',
      desc: 'Findings grouped by severity with evidence and remediation.',
      sections: ['header', 'score', 'findings', 'recommendations', 'disclaimer'] },
    { id: 'network', name: 'Network Overview', icon: 'map',
      desc: 'Segment layout, device distribution and service exposure profile.',
      sections: ['header', 'scope', 'networkOverview', 'assets', 'disclaimer'] }
  ];

  const DISCLAIMER = 'This assessment was performed only against assets included in the authorized scope.';

  function methodologyFor(profileId) {
    const p = CT.engines.scanner.profileById(profileId);
    return {
      profile: p ? p.name : profileId,
      description: p ? p.description : '',
      checks: p ? p.stages.map((s) => CT.engines.scanner.STAGE_LABEL[s] || s) : [],
      excluded: [
        'No exploitation, authentication attempts or credential testing was performed.',
        'No configuration on any target system was modified.',
        'Findings describe observed configuration state, not confirmed compromise.'
      ]
    };
  }

  /** Assemble a fully self-describing report model from an assessment. */
  function build(typeId, assessment) {
    const type = TYPES.find((t) => t.id === typeId) || TYPES[0];
    const findings = assessment.findings || [];
    const assets = assessment.assets || [];
    const bySeverity = {};
    CT.data.SEVERITIES.forEach((s) => { bySeverity[s] = findings.filter((f) => f.severity === s); });

    const recommendations = buildRecommendations(findings);

    return {
      type: type.id, typeName: type.name, sections: type.sections,
      generatedAt: Date.now(),
      simulated: !!assessment.simulated,
      assessment: {
        number: assessment.number, id: assessment.id,
        startedAt: assessment.startedAt, endedAt: assessment.endedAt,
        durationMs: assessment.durationMs, mode: assessment.mode,
        profile: assessment.profileName, profileId: assessment.profileId,
        scope: assessment.scopeLabel, environment: assessment.environmentName,
        authorizedBy: assessment.authorization
      },
      methodology: methodologyFor(assessment.profileId),
      score: assessment.score,
      assets, findings, bySeverity, recommendations,
      stats: {
        assets: assets.length,
        reachable: assets.filter((a) => a.status !== 'unreachable').length,
        services: assets.reduce((a, x) => a + (x.services || []).length, 0),
        findings: findings.length,
        unknownAssets: assets.filter((a) => a.inInventory === false).length
      },
      disclaimer: DISCLAIMER
    };
  }

  /** Collapse per-finding remediation into a deduplicated, ranked action list. */
  function buildRecommendations(findings) {
    const map = new Map();
    findings.forEach((f) => {
      (CT.data.rule(f.ruleId).remediation || []).forEach((r) => {
        if (!map.has(r)) map.set(r, { text: r, count: 0, worst: 'informational', findings: [] });
        const e = map.get(r);
        e.count++;
        e.findings.push(f.id);
        if (CT.data.SEV_RANK[f.severity] < CT.data.SEV_RANK[e.worst]) e.worst = f.severity;
      });
    });
    return Array.from(map.values()).sort((a, b) => {
      const d = CT.data.SEV_RANK[a.worst] - CT.data.SEV_RANK[b.worst];
      return d !== 0 ? d : b.count - a.count;
    });
  }

  /* -- Exporters ----------------------------------------------------------- */
  function toJSON(model) {
    return JSON.stringify({
      tool: 'CheckerTracker', schema: 'checkertracker.report/1',
      generatedAt: new Date(model.generatedAt).toISOString(),
      dataOrigin: model.simulated ? 'SIMULATED — demo environment, no real systems were contacted'
                                  : 'Observed within the authorized scope',
      reportType: model.typeName,
      assessment: Object.assign({}, model.assessment, {
        startedAt: new Date(model.assessment.startedAt).toISOString(),
        endedAt: model.assessment.endedAt ? new Date(model.assessment.endedAt).toISOString() : null
      }),
      methodology: model.methodology,
      score: model.score,
      statistics: model.stats,
      assets: model.assets.map((a) => ({
        id: a.id, hostname: a.hostname, ip: a.ip, ipv6: a.ipv6, mac: a.mac, vendor: a.vendor,
        deviceType: a.deviceType, os: a.os, owner: a.owner, inInventory: a.inInventory !== false,
        status: a.status,
        firstSeen: new Date(a.firstSeen).toISOString(), lastSeen: new Date(a.lastSeen).toISOString(),
        services: (a.services || []).map((s) => ({
          port: s.port, protocol: s.proto, service: s.name, product: s.product, version: s.version
        })),
        tls: a.tls ? { port: a.tls.port, protocols: a.tls.protocols, cipher: a.tls.cipher,
          certificate: a.tls.cert ? {
            subjectCN: a.tls.cert.subjectCN, issuerCN: a.tls.cert.issuerCN,
            notBefore: new Date(a.tls.cert.notBefore).toISOString(),
            notAfter: new Date(a.tls.cert.notAfter).toISOString(),
            signatureAlgorithm: a.tls.cert.sigAlg, keyAlgorithm: a.tls.cert.keyAlg,
            keyBits: a.tls.cert.keyBits, selfSigned: a.tls.cert.selfSigned, san: a.tls.cert.san
          } : null } : null
      })),
      findings: model.findings.map((f) => {
        const rt = CT.data.rule(f.ruleId);
        return {
          id: f.id, ruleId: f.ruleId, title: f.title, severity: f.severity, category: f.category,
          confidence: f.confidence, status: f.status || 'open',
          asset: f.assetLabel, assetIp: f.assetIp, service: f.service,
          discoveredAt: new Date(f.discoveredAt).toISOString(),
          detail: f.detail, description: rt.description, impact: rt.impact,
          remediation: rt.remediation, references: rt.references,
          evidence: f.evidence, notes: f.notes || [], assignee: f.assignee || null
        };
      }),
      recommendations: model.recommendations.map((r) => ({ action: r.text, appliesTo: r.count, highestSeverity: r.worst })),
      disclaimer: model.disclaimer
    }, null, 2);
  }

  function toCSV(model, which) {
    const q = CT.util.escapeCsv;
    const rows = [];
    if (which === 'assets') {
      rows.push(['hostname', 'ip', 'ipv6', 'mac', 'vendor', 'device_type', 'os', 'owner',
                 'in_inventory', 'status', 'open_services', 'service_list', 'first_seen', 'last_seen'].join(','));
      model.assets.forEach((a) => rows.push([
        q(a.hostname || ''), q(a.ip), q(a.ipv6 || ''), q(a.mac || ''), q(a.vendor || ''),
        q(a.deviceType), q(a.os || ''), q(a.owner || ''), a.inInventory !== false ? 'yes' : 'no',
        q(a.status || ''), (a.services || []).length,
        q((a.services || []).map((s) => s.port + '/' + s.proto).join(' ')),
        q(new Date(a.firstSeen).toISOString()), q(new Date(a.lastSeen).toISOString())
      ].join(',')));
    } else {
      rows.push(['finding_id', 'rule_id', 'title', 'severity', 'category', 'confidence', 'status',
                 'asset', 'asset_ip', 'service', 'discovered_at', 'detail', 'remediation'].join(','));
      model.findings.forEach((f) => rows.push([
        q(f.id), q(f.ruleId), q(f.title), f.severity, q(f.category), f.confidence, f.status || 'open',
        q(f.assetLabel), q(f.assetIp || ''), q(f.service || ''),
        q(new Date(f.discoveredAt).toISOString()), q(f.detail || ''),
        q((CT.data.rule(f.ruleId).remediation || []).join(' | '))
      ].join(',')));
    }
    return rows.join('\r\n');
  }

  return { TYPES, build, buildRecommendations, toJSON, toCSV, DISCLAIMER, methodologyFor };
})();
